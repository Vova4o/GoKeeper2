package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/vova4o/gokeeper2/internal/server/models"
	"github.com/vova4o/gokeeper2/package/jwtauth"
	"github.com/vova4o/gokeeper2/package/logger"
	"github.com/vova4o/gokeeper2/package/passwordhash"
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

func TestRecordData(t *testing.T) {
	tests := []struct {
		name    string
		userID  int
		data    models.DataToPass
		mocks   func(*MockStorager)
		wantErr bool
	}{
		{
			name:   "successful record",
			userID: 1,
			data: models.DataToPass{
				DataType: models.DataTypeLoginPassword,
				Data:     "test data",
			},
			mocks: func(m *MockStorager) {
				m.On("FindUserByID", mock.Anything, 1).Return(&models.User{UserID: 1}, nil)
				m.On("SaveData", mock.Anything, 1, models.DataTypeLoginPassword, "test data").Return(nil)
			},
			wantErr: false,
		},
		{
			name:   "user not found",
			userID: 2,
			data: models.DataToPass{
				DataType: models.DataTypeLoginPassword,
				Data:     "test data",
			},
			mocks: func(m *MockStorager) {
				m.On("FindUserByID", mock.Anything, 2).Return(nil, errors.New("user not found"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorager := new(MockStorager)
			logger := logger.NewLogger("info")
			service := &Service{stor: mockStorager, logger: logger}

			tt.mocks(mockStorager)

			err := service.RecordData(context.Background(), tt.userID, tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockStorager.AssertExpectations(t)
		})
	}
}

func TestReadData(t *testing.T) {
	tests := []struct {
		name     string
		userID   int
		dataType models.DataType
		mocks    func(*MockStorager)
		want     []*models.DataToPass
		wantErr  bool
	}{
		{
			name:     "successful read",
			userID:   1,
			dataType: models.DataTypeLoginPassword,
			mocks: func(m *MockStorager) {
				m.On("FindUserByID", mock.Anything, 1).Return(&models.User{UserID: 1}, nil)
				m.On("ReadData", mock.Anything, 1, models.DataTypeLoginPassword).Return([]*models.PrivateInfo{
					{DBID: 1, Data: "test data"},
				}, nil)
			},
			want: []*models.DataToPass{
				{DBID: 1, DataType: models.DataTypeLoginPassword, Data: "test data"},
			},
			wantErr: false,
		},
		{
			name:     "user not found",
			userID:   2,
			dataType: models.DataTypeLoginPassword,
			mocks: func(m *MockStorager) {
				m.On("FindUserByID", mock.Anything, 2).Return(nil, errors.New("user not found"))
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorager := new(MockStorager)
			logger := logger.NewLogger("info")
			service := &Service{stor: mockStorager, logger: logger}

			tt.mocks(mockStorager)

			got, err := service.ReadData(context.Background(), tt.userID, tt.dataType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
			mockStorager.AssertExpectations(t)
		})
	}
}

func TestUpdateData(t *testing.T) {
	tests := []struct {
		name    string
		dataID  int
		data    string
		mocks   func(*MockStorager)
		wantErr bool
	}{
		{
			name:   "successful update",
			dataID: 1,
			data:   "updated data",
			mocks: func(m *MockStorager) {
				m.On("UpdateData", mock.Anything, 1, "updated data").Return(nil)
			},
			wantErr: false,
		},
		{
			name:   "update error",
			dataID: 2,
			data:   "updated data",
			mocks: func(m *MockStorager) {
				m.On("UpdateData", mock.Anything, 2, "updated data").Return(errors.New("update error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorager := new(MockStorager)
			logger := logger.NewLogger("info")
			service := &Service{stor: mockStorager, logger: logger}

			tt.mocks(mockStorager)

			err := service.UpdateData(context.Background(), tt.dataID, tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockStorager.AssertExpectations(t)
		})
	}
}

func TestDeleteData(t *testing.T) {
	tests := []struct {
		name    string
		dataID  int
		mocks   func(*MockStorager)
		wantErr bool
	}{
		{
			name:   "successful delete",
			dataID: 1,
			mocks: func(m *MockStorager) {
				m.On("DeleteData", mock.Anything, 1).Return(nil)
			},
			wantErr: false,
		},
		{
			name:   "delete error",
			dataID: 2,
			mocks: func(m *MockStorager) {
				m.On("DeleteData", mock.Anything, 2).Return(errors.New("delete error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorager := new(MockStorager)
			logger := logger.NewLogger("info")
			service := &Service{stor: mockStorager, logger: logger}

			tt.mocks(mockStorager)

			err := service.DeleteData(context.Background(), tt.dataID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockStorager.AssertExpectations(t)
		})
	}
}

func TestMasterPasswordCheckOrStore(t *testing.T) {
	tests := []struct {
		name           string
		masterPassword string
		userID         int
		mocks          func(*MockStorager)
		want           bool
		wantErr        bool
	}{
		{
			name:           "successful store new master password",
			masterPassword: "test_master_password",
			userID:         1,
			mocks: func(m *MockStorager) {
				// Имитируем отсутствие мастер-пароля в БД
				m.On("CheckMasterPassword", mock.Anything, 1).
					Return("", sql.ErrNoRows)
				// Имитируем успешное сохранение
				m.On("StoreMasterPassword", mock.Anything, 1, mock.AnythingOfType("string")).
					Return(nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name:           "successful check existing master password",
			masterPassword: "test_master_password",
			userID:         1,
			mocks: func(m *MockStorager) {
				// Возвращаем существующий хеш (используем реальный хеш для проверки)
				hashedPassword, _ := passwordhash.HashPassword("test_master_password")
				m.On("CheckMasterPassword", mock.Anything, 1).
					Return(hashedPassword, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name:           "incorrect master password",
			masterPassword: "wrong_password",
			userID:         1,
			mocks: func(m *MockStorager) {
				// Возвращаем хеш от другого пароля
				hashedPassword, _ := passwordhash.HashPassword("correct_password")
				m.On("CheckMasterPassword", mock.Anything, 1).
					Return(hashedPassword, nil)
			},
			want:    false,
			wantErr: false,
		},
		{
			name:           "db error on check",
			masterPassword: "test_master_password",
			userID:         1,
			mocks: func(m *MockStorager) {
				m.On("CheckMasterPassword", mock.Anything, 1).
					Return("", errors.New("db error"))
			},
			want:    false,
			wantErr: true,
		},
		{
			name:           "db error on store",
			masterPassword: "test_master_password",
			userID:         1,
			mocks: func(m *MockStorager) {
				m.On("CheckMasterPassword", mock.Anything, 1).
					Return("", sql.ErrNoRows)
				m.On("StoreMasterPassword", mock.Anything, 1, mock.AnythingOfType("string")).
					Return(errors.New("db error"))
			},
			want:    false,
			wantErr: true,
		},
		{
			name:           "missing user ID in context",
			masterPassword: "test_master_password",
			userID:         0, // будет использован пустой контекст
			mocks: func(m *MockStorager) {
				// нет моков, так как ошибка произойдет раньше
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorager := new(MockStorager)
			logger := logger.NewLogger("info")
			service := &Service{stor: mockStorager, logger: logger}

			tt.mocks(mockStorager)

			var ctx context.Context
			if tt.userID > 0 {
				ctx = context.WithValue(context.Background(), models.UserIDKey, tt.userID)
			} else {
				ctx = context.Background()
			}

			got, err := service.MasterPasswordCheckOrStore(ctx, tt.masterPassword)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}

			mockStorager.AssertExpectations(t)
		})
	}
}

func TestAuthenticateUser(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		mockUser      *models.User
		mockSetup     func(*MockStorager, *models.User)
		expectedUser  *models.UserRegesred
		expectedError string
	}{
		{
			name:     "successful authentication",
			username: "testuser",
			password: "testpass",
			mockUser: &models.User{
				UserID:       1,
				Username:     "testuser",
				PasswordHash: "",
			},
			mockSetup: func(m *MockStorager, user *models.User) {
				// Хешируем пароль для мока
				hashedPassword, _ := passwordhash.HashPassword("testpass")
				user.PasswordHash = hashedPassword

				m.On("FindUserByName", mock.Anything, "testuser").
					Return(user, nil)
				m.On("SaveRefreshToken", mock.Anything, mock.MatchedBy(func(token models.RefreshToken) bool {
					return token.UserID == user.UserID && !token.IsRevoked
				})).Return(nil)
			},
			expectedUser: &models.UserRegesred{
				UserID: 1,
				// Токены будут проверены отдельно
			},
			expectedError: "",
		},
		{
			name:     "user not found",
			username: "nonexistent",
			password: "testpass",
			mockUser: nil,
			mockSetup: func(m *MockStorager, user *models.User) {
				m.On("FindUserByName", mock.Anything, "nonexistent").
					Return(nil, errors.New("user not found"))
			},
			expectedUser:  nil,
			expectedError: "user not found",
		},
		{
			name:     "invalid password",
			username: "testuser",
			password: "wrongpass",
			mockUser: &models.User{
				UserID:       1,
				Username:     "testuser",
				PasswordHash: "", // Будет установлен в mockSetup
			},
			mockSetup: func(m *MockStorager, user *models.User) {
				// Хешируем правильный пароль для мока
				hashedPassword, _ := passwordhash.HashPassword("testpass")
				user.PasswordHash = hashedPassword

				m.On("FindUserByName", mock.Anything, "testuser").
					Return(user, nil)
			},
			expectedUser:  nil,
			expectedError: "invalid password",
		},
		{
			name:     "error saving refresh token",
			username: "testuser",
			password: "testpass",
			mockUser: &models.User{
				UserID:       1,
				Username:     "testuser",
				PasswordHash: "", // Будет установлен в mockSetup
			},
			mockSetup: func(m *MockStorager, user *models.User) {
				hashedPassword, _ := passwordhash.HashPassword("testpass")
				user.PasswordHash = hashedPassword

				m.On("FindUserByName", mock.Anything, "testuser").
					Return(user, nil)
				m.On("SaveRefreshToken", mock.Anything, mock.Anything).
					Return(errors.New("failed to save token"))
			},
			expectedUser:  nil,
			expectedError: "failed to save token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorager := new(MockStorager)
			logger := logger.NewLogger("info")
			jwtService := jwtauth.NewJWTService("test_secret", "test_issuer")
			service := &Service{
				stor:       mockStorager,
				jwtService: jwtService,
				logger:     logger,
			}

			tt.mockSetup(mockStorager, tt.mockUser)

			user, err := service.AuthenticateUser(context.Background(), tt.username, tt.password)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.expectedUser.UserID, user.UserID)

				// Проверяем, что токены не пустые
				assert.NotEmpty(t, user.AccessToken)
				assert.NotEmpty(t, user.RefreshToken)

				// Проверяем валидность токенов
				claims, err := jwtService.ParseToken(user.AccessToken)
				userIDInt := int(claims["user_id"].(float64))
				assert.NoError(t, err)
				assert.Equal(t, tt.mockUser.UserID, userIDInt)

				// Проверяем refresh token
				claims, err = jwtService.ParseToken(user.RefreshToken)
				userIDInt = int(claims["user_id"].(float64))
				assert.NoError(t, err)
				assert.Equal(t, tt.mockUser.UserID, userIDInt)
			}

			mockStorager.AssertExpectations(t)
		})
	}
}
