package handlers

import (
	"context"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/vova4o/gokeeper2/internal/server/models"
	"github.com/vova4o/gokeeper2/package/logger"

	pb "github.com/vova4o/gokeeper2/protobuf/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Claims struct for JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// HandleServiceServer struct
type HandleServiceServer struct {
	pb.UnimplementedAuthServiceServer
	jwtService JWTServicer
	serv       Servicer
	jwtKey     []byte
	logger     *logger.Logger
}

// Servicer interface
type Servicer interface {
	RegisterUser(ctx context.Context, user models.User) (*models.UserRegesred, error)
	MasterPasswordCheckOrStore(ctx context.Context, masterPassword string) (bool, error)
	AuthenticateUser(ctx context.Context, username, password string) (*models.UserRegesred, error)
	RefreshToken(ctx context.Context, refreshToken string) (*models.UserRegesred, error)
	RecordData(ctx context.Context, userID int, data models.DataToPass) error
	ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.DataToPass, error)
}

// JWTServicer interface for JWT service methods
type JWTServicer interface {
	CreateAccessToken(userID int, duration time.Duration) (string, error)
	CreateRefreshToken(userID int, duration time.Duration) (string, error)
	ParseToken(tokenString string) (jwt.MapClaims, error)
	UserIDFromToken(tokenString string) (int, error)
}

// NewHandlersService function
func NewHandlersService(jwtService JWTServicer, serv Servicer, log *logger.Logger) *HandleServiceServer {
	return &HandleServiceServer{
		jwtService: jwtService,
		serv:       serv,
		jwtKey:     []byte("my_secret_key"), // TODO: move to config
		logger:     log,
	}
}

// Register method
func (s *HandleServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Логика регистрации пользователя
	user := models.User{
		Username:     req.Username,
		PasswordHash: req.Password,
	}

	userAfterReg, err := s.serv.RegisterUser(ctx, user)
	if err != nil {
		s.logger.Error("Failed to register user: " + err.Error())
		return nil, err
	}

	if userAfterReg.UserID == 0 {
		s.logger.Error("User already exists")
		return nil, status.Errorf(codes.AlreadyExists, "user already exists")
	}

	return &pb.RegisterResponse{
		UserID:       int64(userAfterReg.UserID),
		Token:        userAfterReg.AccessToken,
		RefreshToken: userAfterReg.RefreshToken,
	}, nil
}

// AuthFuncOverride method
func (s *HandleServiceServer) AuthFuncOverride(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	s.logger.Info("AuthFuncOverride handle called!")

	if info.FullMethod == "/auth.AuthService/Login" || info.FullMethod == "/auth.AuthService/Register" {
		return handler(ctx, req)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.Error("Missing metadata")
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	token := md["authorization"]
	if len(token) == 0 {
		s.logger.Error("Missing token length 0")
		return nil, status.Errorf(codes.Unauthenticated, "missing token")
	}

	s.logger.Info("Auth Handle Token: " + token[0])

	_, err := s.jwtService.ParseToken(token[0])
	if err != nil {
		s.logger.Error("Failed to parse token: " + err.Error())
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	userID, err := s.jwtService.UserIDFromToken(token[0])
	if err != nil {
		s.logger.Error("Failed to get user ID from token: " + err.Error())
		return nil, status.Errorf(codes.Unauthenticated, "invalid token userID")
	}

	s.logger.Info("Auth Handle User ID from token: " + strconv.Itoa(userID))

	ctx = context.WithValue(ctx, models.UserIDKey, userID)

	return handler(ctx, req)
}

// MasterPassword method for checking or storing master password hash
func (s *HandleServiceServer) MasterPassword(ctx context.Context, req *pb.MasterPasswordRequest) (*pb.MasterPasswordResponse, error) {
	// Logick of storring and checking hash of master password
	s.logger.Info("MasterPasswordCheckOrStore handle called!")

	result, err := s.serv.MasterPasswordCheckOrStore(ctx, req.MasterPassword)
	if err != nil {
		s.logger.Error("Failed to check or store master password: " + err.Error())
		return nil, err
	}

	// Idea is to return 401 to client, so that client can ask for master password again

	return &pb.MasterPasswordResponse{
		Success: result,
	}, nil
}

// Login method
func (s *HandleServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	s.logger.Info("Login handle called!")

	userAfterLogin, err := s.serv.AuthenticateUser(ctx, req.Username, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	return &pb.LoginResponse{Token: userAfterLogin.AccessToken, RefreshToken: userAfterLogin.RefreshToken}, nil
}

// RefreshToken method
func (s *HandleServiceServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	s.logger.Info("RefreshToken handle called!")

	userAfterRefresh, err := s.serv.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if err.Error() == "refresh token expired" {
			s.logger.Error("Refresh token expired: " + err.Error())
			return nil, status.Errorf(codes.Unauthenticated, "refresh token expired")
		}
		s.logger.Error("Failed to refresh token: " + err.Error())
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	return &pb.RefreshTokenResponse{
		Token:        userAfterRefresh.AccessToken,
		RefreshToken: userAfterRefresh.RefreshToken,
	}, nil
}

// SendData method for storing data in database
func (s *HandleServiceServer) SendData(ctx context.Context, req *pb.SendDataRequest) (*pb.SendDataResponse, error) {
	s.logger.Info("SendData handle called!")

	userID, ok := ctx.Value(models.UserIDKey).(int)
	if !ok {
		s.logger.Error("Failed to get user ID from context")
		return nil, status.Errorf(codes.Internal, "failed to get user ID from context")
	}

	dataToPass := models.DataToPass{
		DataType: models.DataType(req.Data.DataType),
		Data:     req.Data.StringData,
	}

	err := s.serv.RecordData(ctx, userID, dataToPass)
	if err != nil {
		s.logger.Error("Failed to record data: " + err.Error())
		return nil, status.Errorf(codes.Internal, "failed to record data")
	}

	return &pb.SendDataResponse{Success: true}, nil
}

// ReceiveData method for sending data to client
func (s *HandleServiceServer) ReceiveData(req *pb.ReceiveDataRequest, stream pb.AuthService_ReceiveDataServer) error {
	s.logger.Info("ReceiveData handle called!")

	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		s.logger.Error("Failed to get metadata from context")
		return status.Errorf(codes.Internal, "failed to get metadata from context")
	}

	token := md["authorization"]
	if len(token) == 0 {
		s.logger.Error("Missing token")
		return status.Errorf(codes.Unauthenticated, "missing token")
	}

	userID, err := s.jwtService.UserIDFromToken(token[0])
	if err != nil {
		s.logger.Error("Failed to get user ID from token: " + err.Error())
		return status.Errorf(codes.Unauthenticated, "invalid token userID")
	}

	dataList, err := s.serv.ReadData(stream.Context(), userID, models.DataType(req.DataType))
	if err != nil {
		s.logger.Info("Failed to read data: " + err.Error())
		return status.Errorf(codes.Internal, "failed to read data")
	}

	for _, data := range dataList {
		pbData := &pb.DataToPass{
			DBID:       int64(data.DBID),
			DataType:   pb.DataType(data.DataType),
			StringData: data.Data,
		}

		if err := stream.Send(&pb.ReceiveDataResponse{Data: pbData}); err != nil {
			return status.Errorf(codes.Internal, "failed to send data: %v", err)
		}
	}

	return nil
}
