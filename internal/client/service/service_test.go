package service

import (
    "context"
    "errors"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/vova4o/gokeeper2/package/logger"
)

// MockStorager is a mock implementation of the Storager interface
type MockStorager struct {
    mock.Mock
}

func (m *MockStorager) AddOrReplaceRefreshToken(ctx context.Context, data string) error {
    args := m.Called(ctx, data)
    return args.Error(0)
}

func (m *MockStorager) GetRefreshToken(ctx context.Context) (string, error) {
    args := m.Called(ctx)
    return args.String(0), args.Error(1)
}

func TestAddOrReplaceRefreshToken(t *testing.T) {
    tests := []struct {
        name        string
        inputData   string
        mockError   error
        expectedErr error
    }{
        {
            name:        "successful add",
            inputData:   "test_refresh_token",
            mockError:   nil,
            expectedErr: nil,
        },
        {
            name:        "failed add",
            inputData:   "test_refresh_token",
            mockError:   errors.New("storage error"),
            expectedErr: errors.New("storage error"),
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Создаем новый мок для каждого теста
            mockStorager := new(MockStorager)
            logger := logger.NewLogger("info")
            service := NewService(mockStorager, logger)

            // Настраиваем ожидание для мока
            mockStorager.On("AddOrReplaceRefreshToken", mock.Anything, tt.inputData).Once().Return(tt.mockError)

            // Выполняем тестируемый метод
            err := service.AddOrReplaceRefreshToken(context.Background(), tt.inputData)

            // Проверяем результат
            if tt.expectedErr != nil {
                assert.EqualError(t, err, tt.expectedErr.Error())
            } else {
                assert.NoError(t, err)
            }

            // Проверяем, что все ожидания мока были выполнены
            mockStorager.AssertExpectations(t)
        })
    }
}

func TestGetRefreshToken(t *testing.T) {
    tests := []struct {
        name          string
        mockToken     string
        mockError     error
        expectedToken string
        expectedErr   error
    }{
        {
            name:          "successful get",
            mockToken:     "test_refresh_token",
            mockError:     nil,
            expectedToken: "test_refresh_token",
            expectedErr:   nil,
        },
        {
            name:          "failed get",
            mockToken:     "",
            mockError:     errors.New("storage error"),
            expectedToken: "",
            expectedErr:   errors.New("storage error"),
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Создаем новый мок для каждого теста
            mockStorager := new(MockStorager)
            logger := logger.NewLogger("info")
            service := NewService(mockStorager, logger)

            // Настраиваем ожидание для мока
            mockStorager.On("GetRefreshToken", mock.Anything).Once().Return(tt.mockToken, tt.mockError)

            // Выполняем тестируемый метод
            token, err := service.GetRefreshToken(context.Background())

            // Проверяем результат
            if tt.expectedErr != nil {
                assert.EqualError(t, err, tt.expectedErr.Error())
                assert.Empty(t, token)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedToken, token)
            }

            // Проверяем, что все ожидания мока были выполнены
            mockStorager.AssertExpectations(t)
        })
    }
}