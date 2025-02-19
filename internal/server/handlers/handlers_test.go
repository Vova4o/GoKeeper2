package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vova4o/gokeeper2/internal/server/models"
	"github.com/vova4o/gokeeper2/package/logger"
	pb "github.com/vova4o/gokeeper2/protobuf/auth"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Моки для интерфейсов
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) CreateAccessToken(userID int, duration time.Duration) (string, error) {
	args := m.Called(userID, duration)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) CreateRefreshToken(userID int, duration time.Duration) (string, error) {
	args := m.Called(userID, duration)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ParseToken(tokenString string) (jwt.MapClaims, error) {
	args := m.Called(tokenString)
	if claims, ok := args.Get(0).(jwt.MapClaims); ok {
		return claims, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockJWTService) UserIDFromToken(tokenString string) (int, error) {
	args := m.Called(tokenString)
	return args.Int(0), args.Error(1)
}

type MockService struct {
	mock.Mock
}

func (m *MockService) RegisterUser(ctx context.Context, user models.User) (*models.UserRegesred, error) {
	args := m.Called(ctx, user)
	if res, ok := args.Get(0).(*models.UserRegesred); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) MasterPasswordCheckOrStore(ctx context.Context, masterPassword string) (bool, error) {
	args := m.Called(ctx, masterPassword)
	return args.Bool(0), args.Error(1)
}

func (m *MockService) AuthenticateUser(ctx context.Context, username, password string) (*models.UserRegesred, error) {
	args := m.Called(ctx, username, password)
	if res, ok := args.Get(0).(*models.UserRegesred); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) RefreshToken(ctx context.Context, refreshToken string) (*models.UserRegesred, error) {
	args := m.Called(ctx, refreshToken)
	if res, ok := args.Get(0).(*models.UserRegesred); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) RecordData(ctx context.Context, userID int, data models.DataToPass) error {
	args := m.Called(ctx, userID, data)
	return args.Error(0)
}

func (m *MockService) ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.DataToPass, error) {
	args := m.Called(ctx, userID, dataType)
	if res, ok := args.Get(0).([]*models.DataToPass); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) UpdateData(ctx context.Context, dataID int, data string) error {
	args := m.Called(ctx, dataID, data)
	return args.Error(0)
}

func (m *MockService) DeleteData(ctx context.Context, dataID int) error {
	args := m.Called(ctx, dataID)
	return args.Error(0)
}

// MockAuthServiceReceiveDataServer - мок для стрима
type MockAuthServiceReceiveDataServer struct {
	mock.Mock
	grpc.ServerStream
	ctx context.Context
}

func (m *MockAuthServiceReceiveDataServer) Send(resp *pb.ReceiveDataResponse) error {
	args := m.Called(resp)
	return args.Error(0)
}

func (m *MockAuthServiceReceiveDataServer) Context() context.Context {
	return m.ctx
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.RegisterRequest
		mockResponse  *models.UserRegesred
		mockError     error
		expectedResp  *pb.RegisterResponse
		expectedError error
	}{
		{
			name: "successful registration",
			request: &pb.RegisterRequest{
				Username: "testuser",
				Password: "testpass",
			},
			mockResponse: &models.UserRegesred{
				UserID:       1,
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			mockError: nil,
			expectedResp: &pb.RegisterResponse{
				UserID:       1,
				Token:        "access_token",
				RefreshToken: "refresh_token",
			},
			expectedError: nil,
		},
		{
			name: "user already exists",
			request: &pb.RegisterRequest{
				Username: "existinguser",
				Password: "testpass",
			},
			mockResponse:  &models.UserRegesred{},
			mockError:     nil,
			expectedResp:  nil,
			expectedError: status.Error(codes.AlreadyExists, "user already exists"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			mockServ.On("RegisterUser", mock.Anything, models.User{
				Username:     tt.request.Username,
				PasswordHash: tt.request.Password,
			}).Return(tt.mockResponse, tt.mockError)

			resp, err := handler.Register(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.LoginRequest
		mockResponse  *models.UserRegesred
		mockError     error
		expectedResp  *pb.LoginResponse
		expectedError error
	}{
		{
			name: "successful login",
			request: &pb.LoginRequest{
				Username: "testuser",
				Password: "testpass",
			},
			mockResponse: &models.UserRegesred{
				UserID:       1,
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			mockError: nil,
			expectedResp: &pb.LoginResponse{
				Token:        "access_token",
				RefreshToken: "refresh_token",
			},
			expectedError: nil,
		},
		{
			name: "invalid credentials",
			request: &pb.LoginRequest{
				Username: "wronguser",
				Password: "wrongpass",
			},
			mockResponse:  nil,
			mockError:     status.Error(codes.Unauthenticated, "invalid credentials"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Unauthenticated, "invalid credentials"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			mockServ.On("AuthenticateUser", mock.Anything, tt.request.Username, tt.request.Password).
				Return(tt.mockResponse, tt.mockError)

			resp, err := handler.Login(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestUpdateData(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.DataToPass
		mockError     error
		expectedResp  *pb.SendDataResponse
		expectedError error
	}{
		{
			name: "successful update",
			request: &pb.DataToPass{
				DBID:       1,
				StringData: "test_data",
			},
			mockError: nil,
			expectedResp: &pb.SendDataResponse{
				Success: true,
			},
			expectedError: nil,
		},
		{
			name:          "nil request",
			request:       nil,
			mockError:     nil,
			expectedResp:  nil,
			expectedError: status.Error(codes.InvalidArgument, "data is nil"),
		},
		{
			name: "zero DBID",
			request: &pb.DataToPass{
				DBID:       0,
				StringData: "test_data",
			},
			mockError:     nil,
			expectedResp:  nil,
			expectedError: status.Error(codes.InvalidArgument, "DBID is 0"),
		},
		{
			name: "update error",
			request: &pb.DataToPass{
				DBID:       1,
				StringData: "test_data",
			},
			mockError:     errors.New("database error"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Internal, "failed to update data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			if tt.request != nil && tt.request.DBID != 0 {
				mockServ.On("UpdateData", mock.Anything, int(tt.request.DBID), tt.request.StringData).
					Return(tt.mockError)
			}

			resp, err := handler.UpdateData(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestDeleteData(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.DeleteRequest
		mockError     error
		expectedResp  *pb.SendDataResponse
		expectedError error
	}{
		{
			name: "successful deletion",
			request: &pb.DeleteRequest{
				DBID: 1,
			},
			mockError: nil,
			expectedResp: &pb.SendDataResponse{
				Success: true,
			},
			expectedError: nil,
		},
		{
			name:          "nil request",
			request:       nil,
			mockError:     nil,
			expectedResp:  nil,
			expectedError: status.Error(codes.InvalidArgument, "data is nil"),
		},
		{
			name: "zero DBID",
			request: &pb.DeleteRequest{
				DBID: 0,
			},
			mockError:     nil,
			expectedResp:  nil,
			expectedError: status.Error(codes.InvalidArgument, "DBID is 0"),
		},
		{
			name: "deletion error",
			request: &pb.DeleteRequest{
				DBID: 1,
			},
			mockError:     errors.New("database error"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Internal, "failed to delete data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			if tt.request != nil && tt.request.DBID != 0 {
				mockServ.On("DeleteData", mock.Anything, int(tt.request.DBID)).
					Return(tt.mockError)
			}

			resp, err := handler.DeleteData(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestMasterPasswordCheckOrStore(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.MasterPasswordRequest
		mockResponse  bool
		mockError     error
		expectedResp  *pb.MasterPasswordResponse
		expectedError error
	}{
		{
			name: "successful check",
			request: &pb.MasterPasswordRequest{
				MasterPassword: "test_master_password",
			},
			mockResponse: true,
			mockError:    nil,
			expectedResp: &pb.MasterPasswordResponse{
				Success: true,
			},
			expectedError: nil,
		},
		{
			name: "successful store",
			request: &pb.MasterPasswordRequest{
				MasterPassword: "test_master_password",
			},
			mockResponse: true,
			mockError:    nil,
			expectedResp: &pb.MasterPasswordResponse{
				Success: true,
			},
			expectedError: nil,
		},
		{
			name: "check/store error",
			request: &pb.MasterPasswordRequest{
				MasterPassword: "test_master_password",
			},
			mockResponse:  false,
			mockError:     status.Error(codes.Internal, "failed to check or store master password"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Internal, "failed to check or store master password"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			mockServ.On("MasterPasswordCheckOrStore", mock.Anything, tt.request.MasterPassword).
				Return(tt.mockResponse, tt.mockError)

			resp, err := handler.MasterPassword(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestSendAndReceiveData(t *testing.T) {
	// Создаем тестовый контекст с userID
	userID := 1
	ctx := context.WithValue(context.Background(), models.UserIDKey, userID)

	tests := []struct {
		name         string
		testType     string      // "send" или "receive"
		request      interface{} // может быть *pb.SendDataRequest или *pb.ReceiveDataRequest
		mockSetup    func(*MockJWTService, *MockService)
		expectedResp interface{} // может быть *pb.SendDataResponse или error
		expectedErr  error
		streamSetup  func() *MockAuthServiceReceiveDataServer
	}{
		{
			name:     "successful send data",
			testType: "send",
			request: &pb.SendDataRequest{
				Data: &pb.DataToPass{
					DataType:   pb.DataType_LOGIN_PASSWORD,
					StringData: "test_data",
				},
			},
			mockSetup: func(jwt *MockJWTService, serv *MockService) {
				serv.On("RecordData", mock.Anything, userID, mock.MatchedBy(func(data models.DataToPass) bool {
					return data.DataType == models.DataType(pb.DataType_LOGIN_PASSWORD) &&
						data.Data == "test_data"
				})).Return(nil)
			},
			expectedResp: &pb.SendDataResponse{Success: true},
			expectedErr:  nil,
		},
		{
			name:     "failed send data - record error",
			testType: "send",
			request: &pb.SendDataRequest{
				Data: &pb.DataToPass{
					DataType:   pb.DataType_LOGIN_PASSWORD,
					StringData: "test_data",
				},
			},
			mockSetup: func(jwt *MockJWTService, serv *MockService) {
				serv.On("RecordData", mock.Anything, userID, mock.Anything).
					Return(errors.New("database error"))
			},
			expectedResp: nil,
			expectedErr:  status.Error(codes.Internal, "failed to record data"),
		},
		{
			name:     "successful receive data",
			testType: "receive",
			request: &pb.ReceiveDataRequest{
				DataType: pb.DataType_LOGIN_PASSWORD,
			},
			mockSetup: func(jwt *MockJWTService, serv *MockService) {
				jwt.On("UserIDFromToken", "test_token").Return(userID, nil)
				serv.On("ReadData", mock.Anything, userID, models.DataType(pb.DataType_LOGIN_PASSWORD)).
					Return([]*models.DataToPass{
						{
							DBID:     1,
							DataType: models.DataType(pb.DataType_LOGIN_PASSWORD),
							Data:     "test_data",
						},
					}, nil)
			},
			streamSetup: func() *MockAuthServiceReceiveDataServer {
				md := metadata.New(map[string]string{
					"authorization": "test_token",
				})
				ctx := metadata.NewIncomingContext(context.Background(), md)
				stream := &MockAuthServiceReceiveDataServer{ctx: ctx}
				stream.On("Send", &pb.ReceiveDataResponse{
					Data: &pb.DataToPass{
						DBID:       1,
						DataType:   pb.DataType_LOGIN_PASSWORD,
						StringData: "test_data",
					},
				}).Return(nil)
				return stream
			},
			expectedErr: nil,
		},
		{
			name:     "failed receive data - missing token",
			testType: "receive",
			request: &pb.ReceiveDataRequest{
				DataType: pb.DataType_LOGIN_PASSWORD,
			},
			mockSetup: func(jwt *MockJWTService, serv *MockService) {},
			streamSetup: func() *MockAuthServiceReceiveDataServer {
				// Создаем пустые метаданные без токена авторизации
				md := metadata.New(map[string]string{})
				ctx := metadata.NewIncomingContext(context.Background(), md)
				stream := &MockAuthServiceReceiveDataServer{ctx: ctx}
				return stream
			},
			expectedErr: status.Error(codes.Unauthenticated, "missing token"),
		},
		{
			name:     "failed receive data - invalid metadata",
			testType: "receive",
			request: &pb.ReceiveDataRequest{
				DataType: pb.DataType_LOGIN_PASSWORD,
			},
			mockSetup: func(jwt *MockJWTService, serv *MockService) {},
			streamSetup: func() *MockAuthServiceReceiveDataServer {
				// Создаем контекст без метаданных
				stream := &MockAuthServiceReceiveDataServer{ctx: context.Background()}
				return stream
			},
			expectedErr: status.Error(codes.Internal, "failed to get metadata from context"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			// Настраиваем моки
			tt.mockSetup(mockJWT, mockServ)

			switch tt.testType {
			case "send":
				req := tt.request.(*pb.SendDataRequest)
				resp, err := handler.SendData(ctx, req)

				if tt.expectedErr != nil {
					assert.Error(t, err)
					assert.Equal(t, tt.expectedErr.Error(), err.Error())
					assert.Nil(t, resp)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedResp, resp)
				}

			case "receive":
				req := tt.request.(*pb.ReceiveDataRequest)
				stream := tt.streamSetup()
				err := handler.ReceiveData(req, stream)

				if tt.expectedErr != nil {
					assert.Error(t, err)
					assert.Equal(t, tt.expectedErr.Error(), err.Error())
				} else {
					assert.NoError(t, err)
				}
				if stream != nil {
					stream.AssertExpectations(t)
				}
			}

			mockJWT.AssertExpectations(t)
			mockServ.AssertExpectations(t)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.RefreshTokenRequest
		mockResponse  *models.UserRegesred
		mockError     error
		expectedResp  *pb.RefreshTokenResponse
		expectedError error
	}{
		{
			name: "successful refresh",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "valid_refresh_token",
			},
			mockResponse: &models.UserRegesred{
				UserID:       1,
				AccessToken:  "new_access_token",
				RefreshToken: "new_refresh_token",
			},
			mockError: nil,
			expectedResp: &pb.RefreshTokenResponse{
				Token:        "new_access_token",
				RefreshToken: "new_refresh_token",
			},
			expectedError: nil,
		},
		{
			name: "expired refresh token",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "expired_token",
			},
			mockResponse:  nil,
			mockError:     errors.New("refresh token expired"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Unauthenticated, "refresh token expired"),
		},
		{
			name: "invalid refresh token",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "invalid_token",
			},
			mockResponse:  nil,
			mockError:     errors.New("invalid token"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Unauthenticated, "invalid token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			mockServ.On("RefreshToken", mock.Anything, tt.request.RefreshToken).
				Return(tt.mockResponse, tt.mockError)

			resp, err := handler.RefreshToken(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestAuthFuncOverride(t *testing.T) {
	tests := []struct {
		name          string
		fullMethod    string
		setupMetadata func() context.Context
		mockSetup     func(*MockJWTService)
		expectedErr   error
	}{
		{
			name:       "login method - bypass auth",
			fullMethod: "/auth.AuthService/Login",
			setupMetadata: func() context.Context {
				return context.Background()
			},
			mockSetup:   func(jwt *MockJWTService) {},
			expectedErr: nil,
		},
		{
			name:       "register method - bypass auth",
			fullMethod: "/auth.AuthService/Register",
			setupMetadata: func() context.Context {
				return context.Background()
			},
			mockSetup:   func(jwt *MockJWTService) {},
			expectedErr: nil,
		},
		{
			name:       "protected method - valid token",
			fullMethod: "/auth.AuthService/ProtectedMethod",
			setupMetadata: func() context.Context {
				md := metadata.New(map[string]string{
					"authorization": "valid_token",
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			mockSetup: func(jwt *MockJWTService) {
				claims := make(map[string]interface{})
				jwt.On("ParseToken", "valid_token").Return(claims, nil)
				jwt.On("UserIDFromToken", "valid_token").Return(1, nil)
			},
			expectedErr: nil,
		},
		{
			name:       "protected method - missing metadata",
			fullMethod: "/auth.AuthService/ProtectedMethod",
			setupMetadata: func() context.Context {
				return context.Background()
			},
			mockSetup:   func(jwt *MockJWTService) {},
			expectedErr: status.Error(codes.Unauthenticated, "missing metadata"),
		},
		{
			name:       "protected method - missing token",
			fullMethod: "/auth.AuthService/ProtectedMethod",
			setupMetadata: func() context.Context {
				md := metadata.New(map[string]string{})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			mockSetup:   func(jwt *MockJWTService) {},
			expectedErr: status.Error(codes.Unauthenticated, "missing token"),
		},
		{
			name:       "protected method - invalid token",
			fullMethod: "/auth.AuthService/ProtectedMethod",
			setupMetadata: func() context.Context {
				md := metadata.New(map[string]string{
					"authorization": "invalid_token",
				})
				return metadata.NewIncomingContext(context.Background(), md)
			},
			mockSetup: func(jwt *MockJWTService) {
				jwt.On("ParseToken", "invalid_token").Return(nil, errors.New("invalid token"))
			},
			expectedErr: status.Error(codes.Unauthenticated, "invalid token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			// Настраиваем моки
			tt.mockSetup(mockJWT)

			// Создаем тестовый контекст с метаданными
			ctx := tt.setupMetadata()

			// Создаем тестовый обработчик
			testHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "test_response", nil
			}

			// Вызываем AuthFuncOverride
			resp, err := handler.AuthFuncOverride(ctx, "test_request", &grpc.UnaryServerInfo{
				FullMethod: tt.fullMethod,
			}, testHandler)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "test_response", resp)
			}

			mockJWT.AssertExpectations(t)
		})
	}
}
