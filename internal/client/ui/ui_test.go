package ui

import (
    "context"
    "testing"

    "fyne.io/fyne/v2/test"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/vova4o/gokeeper2/internal/client/models"
    "github.com/vova4o/gokeeper2/package/logger"
)

// MockGRPCClient реализует интерфейс GRPCClienter для тестирования
type MockGRPCClient struct {
    mock.Mock
}

func (m *MockGRPCClient) Register(ctx context.Context, user models.RegisterAndLogin) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

func (m *MockGRPCClient) Login(ctx context.Context, user models.RegisterAndLogin) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

func (m *MockGRPCClient) MasterPasswordStoreOrCheck(ctx context.Context, masterPassword string) (bool, error) {
    args := m.Called(ctx, masterPassword)
    return args.Bool(0), args.Error(1)
}

func (m *MockGRPCClient) AddDataToServer(ctx context.Context, data models.Data) error {
    args := m.Called(ctx, data)
    return args.Error(0)
}

func (m *MockGRPCClient) GetDataFromServer(ctx context.Context, dataType models.DataTypes) ([]models.Data, error) {
    args := m.Called(ctx, dataType)
    return args.Get(0).([]models.Data), args.Error(1)
}

func (m *MockGRPCClient) UpdateDataOnServer(ctx context.Context, data models.Data) error {
    args := m.Called(ctx, data)
    return args.Error(0)
}

func (m *MockGRPCClient) DeleteDataFromServer(ctx context.Context, data int) error {
    args := m.Called(ctx, data)
    return args.Error(0)
}

func TestNewUI(t *testing.T) {
    mockClient := new(MockGRPCClient)
    logger := logger.NewLogger("info")
    ctx := context.Background()

    ui := NewUI(ctx, mockClient, logger)

    assert.NotNil(t, ui)
    assert.Equal(t, ctx, ui.ctx)
    assert.Equal(t, mockClient, ui.handler)
    assert.Equal(t, logger, ui.logger)
}

func TestShowBankCards(t *testing.T) {
    mockClient := new(MockGRPCClient)
    logger := logger.NewLogger("info")
    ctx := context.Background()
    ui := NewUI(ctx, mockClient, logger)

    // Подготавливаем тестовые данные
    testCards := []models.Data{
        {
            DBID:     1,
            DataType: models.DataTypeBankCard,
            Data: models.BankCard{
                DBID:       1,
                Title:      "Test Card",
                CardNumber: "1234 5678 9012 3456",
                ExpiryDate: "12/24",
                Cvv:        "123",
            },
        },
    }

    // Настраиваем мок
    mockClient.On("GetDataFromServer", ctx, models.DataTypeBankCard).Return(testCards, nil)

    // Создаем тестовое окно
    testWindow := test.NewWindow(nil)
    defer testWindow.Close()

    // Вызываем тестируемый метод
    result := ui.showBankCards()

    // Добавляем результат в тестовое окно
    testWindow.SetContent(result)

    // Проверяем, что мок был вызван
    mockClient.AssertExpectations(t)
}

func TestShowPasswords(t *testing.T) {
    mockClient := new(MockGRPCClient)
    logger := logger.NewLogger("info")
    ctx := context.Background()
    ui := NewUI(ctx, mockClient, logger)

    // Подготавливаем тестовые данные
    testPasswords := []models.Data{
        {
            DBID:     1,
            DataType: models.DataTypeLoginPassword,
            Data: models.LoginPassword{
                DBID:     1,
                Title:    "Test Password",
                Login:    "testuser",
                Password: "testpass",
            },
        },
    }

    // Настраиваем мок
    mockClient.On("GetDataFromServer", ctx, models.DataTypeLoginPassword).Return(testPasswords, nil)

    // Создаем тестовое окно
    testWindow := test.NewWindow(nil)
    defer testWindow.Close()

    // Вызываем тестируемый метод
    result := ui.showPasswords()

    // Добавляем результат в тестовое окно
    testWindow.SetContent(result)

    // Проверяем, что мок был вызван
    mockClient.AssertExpectations(t)
}