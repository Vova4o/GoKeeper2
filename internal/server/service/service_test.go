package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/vova4o/gokeeper2/internal/server/models"
	"github.com/vova4o/gokeeper2/package/jwtauth"
	"github.com/vova4o/gokeeper2/package/logger"
)

type MockStorager struct {
	mock.Mock
}

func (m *MockStorager) CreateUser(ctx context.Context, user models.User) (int, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockStorager) SaveRefreshToken(ctx context.Context, userRefresh models.RefreshToken) error {
	args := m.Called(ctx, userRefresh)
	return args.Error(0)
}

func (m *MockStorager) FindUserByID(ctx context.Context, userID int) (*models.User, error) {
	args := m.Called(ctx, userID)
	if user, ok := args.Get(0).(*models.User); ok {
		return user, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorager) FindUserByName(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if user, ok := args.Get(0).(*models.User); ok {
		return user, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorager) CheckMasterPassword(ctx context.Context, userID int) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockStorager) StoreMasterPassword(ctx context.Context, userID int, masterPasswordHash string) error {
	args := m.Called(ctx, userID, masterPasswordHash)
	return args.Error(0)
}

func (m *MockStorager) GetRefreshTokens(ctx context.Context, userID int) ([]models.RefreshToken, error) {
	args := m.Called(ctx, userID)
	if tokens, ok := args.Get(0).([]models.RefreshToken); ok {
		return tokens, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorager) GetRefreshToken(ctx context.Context, token string) (models.RefreshToken, error) {
	args := m.Called(ctx, token)
	if token, ok := args.Get(0).(models.RefreshToken); ok {
		return token, args.Error(1)
	}
	return models.RefreshToken{}, args.Error(1)
}

func (m *MockStorager) DeleteRefreshToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Mock method for SaveData
func (m *MockStorager) SaveData(ctx context.Context, userID int, dataType models.DataType, data string) error {
	args := m.Called(ctx, userID, dataType, data)
	return args.Error(0)
}

func (m *MockStorager) ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.PrivateInfo, error) {
	args := m.Called(ctx, userID, dataType)
	if data, ok := args.Get(0).([]*models.PrivateInfo); ok {
		return data, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorager) FindUser(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if user, ok := args.Get(0).(*models.User); ok {
		return user, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorager) UpdateData(ctx context.Context, dataID int, data string) error {
	args := m.Called(ctx, dataID, data)
	return args.Error(0)
}

func (m *MockStorager) DeleteData(ctx context.Context, dataID int) error {
	args := m.Called(ctx, dataID)
	return args.Error(0)
}

func TestRegisterUser(t *testing.T) {
	mockStorager := new(MockStorager)
	logger := logger.NewLogger("info")
	jwtService := jwtauth.NewJWTService("secret", "issuer")
	service := &Service{
		stor:       mockStorager,
		jwtService: jwtService,
		logger:     logger,
	}

	user := models.User{
		Username:     "testuser",
		PasswordHash: "password",
	}

	mockStorager.On("CreateUser", mock.Anything, mock.Anything).Return(1, nil)
	mockStorager.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(nil)

	registeredUser, err := service.RegisterUser(context.Background(), user)
	assert.NoError(t, err)
	assert.NotNil(t, registeredUser)
	assert.Equal(t, 1, registeredUser.UserID)
	mockStorager.AssertExpectations(t)
}

// func TestMasterPasswordCheckOrStore(t *testing.T) {
// 	mockStorager := new(MockStorager)
// 	logger := logger.NewLogger("info")
// 	jwtService := jwtauth.NewJWTService("secret", "issuer")
// 	service := &Service{
// 		stor:       mockStorager,
// 		jwtService: jwtService,
// 		logger:     logger,
// 	}

// 	token, _ := jwtService.CreateAccessToken(1, time.Minute*60)
// 	masterPassword := "masterpassword"

// 	md := metadata.New(map[string]string{"authorization": token})
// 	ctx := metadata.NewOutgoingContext(context.Background(), md)

// 	mockStorager.On("CheckMasterPassword", mock.Anything, mock.Anything).Return("", errors.New("record not found"))
// 	mockStorager.On("StoreMasterPassword", mock.Anything, mock.Anything, mock.Anything).Return(nil)

// 	result, err := service.MasterPasswordCheckOrStore(ctx, masterPassword)
// 	assert.NoError(t, err)
// 	assert.True(t, result)
// 	mockStorager.AssertExpectations(t)
// }

func TestRefreshToken(t *testing.T) {
	mockStorager := new(MockStorager)
	logger := logger.NewLogger("info")
	jwtService := jwtauth.NewJWTService("secret", "issuer")
	service := &Service{
		stor:       mockStorager,
		jwtService: jwtService,
		logger:     logger,
	}

	userID := 1
	refreshToken, _ := jwtService.CreateRefreshToken(userID, time.Hour*24*7)
	validTokens := []models.RefreshToken{
		{UserID: userID, Token: refreshToken, IsRevoked: false},
	}

	mockStorager.On("GetRefreshTokens", mock.Anything, userID).Return(validTokens, nil)
	mockStorager.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(nil)

	userAfterRefresh, err := service.RefreshToken(context.Background(), refreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, userAfterRefresh)
	assert.Equal(t, userID, userAfterRefresh.UserID)
	mockStorager.AssertExpectations(t)
}

func TestRefreshToken_RevokedToken(t *testing.T) {
	mockStorager := new(MockStorager)
	logger := logger.NewLogger("info")
	jwtService := jwtauth.NewJWTService("secret", "issuer")
	service := &Service{
		stor:       mockStorager,
		jwtService: jwtService,
		logger:     logger,
	}

	userID := 1
	refreshToken, _ := jwtService.CreateRefreshToken(userID, time.Hour*24*7)
	revokedTokens := []models.RefreshToken{
		{UserID: userID, Token: refreshToken, IsRevoked: true},
	}

	mockStorager.On("GetRefreshTokens", mock.Anything, userID).Return(revokedTokens, nil)
	mockStorager.On("DeleteRefreshToken", mock.Anything, refreshToken).Return(nil)

	userAfterRefresh, err := service.RefreshToken(context.Background(), refreshToken)
	assert.Error(t, err)
	assert.Nil(t, userAfterRefresh)
	mockStorager.AssertExpectations(t)
}

func TestRefreshToken_ExpiredToken(t *testing.T) {
	mockStorager := new(MockStorager)
	logger := logger.NewLogger("info")
	jwtService := jwtauth.NewJWTService("secret", "issuer")
	service := &Service{
		stor:       mockStorager,
		jwtService: jwtService,
		logger:     logger,
	}

	userID := 1
	// Create a refresh token with a very short expiration time
	refreshToken, _ := jwtService.CreateRefreshToken(userID, time.Second*1)

	// Wait for the token to expire
	time.Sleep(time.Second * 2)

	// Mock the DeleteRefreshToken method
	mockStorager.On("DeleteRefreshToken", mock.Anything, refreshToken).Return(nil)

	// Call the RefreshToken function
	userAfterRefresh, err := service.RefreshToken(context.Background(), refreshToken)
	assert.EqualError(t, err, "refresh token expired")
	assert.Nil(t, userAfterRefresh)
	mockStorager.AssertExpectations(t)
}
