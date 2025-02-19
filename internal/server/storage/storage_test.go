package storage

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vova4o/gokeeper2/internal/server/models"
	"github.com/vova4o/gokeeper2/package/logger"
)

func setupTestDB(t *testing.T) (*Storage, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	storage := &Storage{
		db:     db,
		logger: logger.NewLogger("info"),
	}

	return storage, mock, func() {
		db.Close()
	}
}

func TestNewStorage(t *testing.T) {
	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful connection",
			mockSetup: func(mock sqlmock.Sqlmock) {
				// Ожидаем создание таблиц с точным соответствием запросов
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS users \(.*id SERIAL PRIMARY KEY.*\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS refresh_tokens \(.*user_id INTEGER REFERENCES users.*\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS private_infos \(.*user_id INTEGER REFERENCES users.*\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens\(user_id\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_private_infos_user_id ON private_infos\(user_id\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_private_infos_data_type ON private_infos\(data_type\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantErr: false,
		},
		{
			name: "table creation error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS users \(.*\)`).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
		{
			name: "index creation error",
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS users \(.*\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS refresh_tokens \(.*\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS private_infos \(.*\)`).
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id`).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем мок базы данных
			db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
			require.NoError(t, err)
			defer db.Close()

			// Настраиваем ожидаемое поведение
			tt.mockSetup(mock)

			// Создаем хранилище напрямую
			storage := &Storage{
				db:     db,
				logger: logger.NewLogger("info"),
			}

			// Инициализируем хранилище
			err = storage.createTables(context.Background())

			// Проверяем результаты
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)
			}

			// Проверяем, что все ожидаемые запросы были выполнены
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestCreateUser(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		user     models.User
		mockFunc func()
		wantID   int
		wantErr  bool
	}{
		{
			name: "successful creation",
			user: models.User{
				Username:     "testuser",
				PasswordHash: "testhash",
			},
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
				mock.ExpectQuery("INSERT INTO users").
					WithArgs("testuser", "testhash", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantID:  1,
			wantErr: false,
		},
		{
			name: "database error",
			user: models.User{
				Username:     "testuser",
				PasswordHash: "testhash",
			},
			mockFunc: func() {
				mock.ExpectQuery("INSERT INTO users").
					WithArgs("testuser", "testhash", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(sql.ErrConnDone)
			},
			wantID:  0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			id, err := storage.CreateUser(context.Background(), tt.user)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.wantID, id)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantID, id)
			}
		})
	}
}

func TestSaveRefreshToken(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		token    models.RefreshToken
		mockFunc func()
		wantErr  bool
	}{
		{
			name: "successful save",
			token: models.RefreshToken{
				UserID:    1,
				Token:     "testtoken",
				IsRevoked: false,
			},
			mockFunc: func() {
				mock.ExpectExec("INSERT INTO refresh_tokens").
					WithArgs(1, "testtoken", false, sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error",
			token: models.RefreshToken{
				UserID:    1,
				Token:     "testtoken",
				IsRevoked: false,
			},
			mockFunc: func() {
				mock.ExpectExec("INSERT INTO refresh_tokens").
					WithArgs(1, "testtoken", false, sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			err := storage.SaveRefreshToken(context.Background(), tt.token)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetRefreshTokens(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name      string
		userID    int
		mockFunc  func()
		wantCount int
		wantErr   bool
	}{
		{
			name:   "successful retrieval",
			userID: 1,
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"token", "is_revoked"}).
					AddRow("token1", false).
					AddRow("token2", true)
				mock.ExpectQuery("SELECT token, is_revoked FROM refresh_tokens").
					WithArgs(1).
					WillReturnRows(rows)
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:   "no tokens found",
			userID: 1,
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"token", "is_revoked"})
				mock.ExpectQuery("SELECT token, is_revoked FROM refresh_tokens").
					WithArgs(1).
					WillReturnRows(rows)
			},
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			tokens, err := storage.GetRefreshTokens(context.Background(), tt.userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, tokens, tt.wantCount)
			}
		})
	}
}

func TestDeleteRefreshToken(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		token    string
		mockFunc func()
		wantErr  bool
	}{
		{
			name:  "successful deletion",
			token: "testtoken",
			mockFunc: func() {
				mock.ExpectExec("DELETE FROM refresh_tokens").
					WithArgs("testtoken").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name:  "database error",
			token: "testtoken",
			mockFunc: func() {
				mock.ExpectExec("DELETE FROM refresh_tokens").
					WithArgs("testtoken").
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			err := storage.DeleteRefreshToken(context.Background(), tt.token)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSaveData(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		userID   int
		dataType models.DataType
		data     string
		mockFunc func()
		wantErr  bool
	}{
		{
			name:     "successful save",
			userID:   1,
			dataType: models.DataTypeLoginPassword,
			data:     "test data",
			mockFunc: func() {
				mock.ExpectExec("INSERT INTO private_infos").
					WithArgs(1, models.DataTypeLoginPassword, "test data", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name:     "database error",
			userID:   1,
			dataType: models.DataTypeLoginPassword,
			data:     "test data",
			mockFunc: func() {
				mock.ExpectExec("INSERT INTO private_infos").
					WithArgs(1, models.DataTypeLoginPassword, "test data", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			err := storage.SaveData(context.Background(), tt.userID, tt.dataType, tt.data)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadData(t *testing.T) {
    storage, mock, teardown := setupTestDB(t)
    defer teardown()

    tests := []struct {
        name      string
        userID    int
        dataType  models.DataType
        mockFunc  func()
        wantCount int
        wantErr   bool
    }{
        {
            name:     "successful read",
            userID:   1,
            dataType: models.DataTypeLoginPassword,
            mockFunc: func() {
                rows := sqlmock.NewRows([]string{"id", "user_id", "data_type", "data"}).
                    AddRow(1, 1, models.DataTypeLoginPassword, "test data 1").
                    AddRow(2, 1, models.DataTypeLoginPassword, "test data 2")
                mock.ExpectQuery("SELECT id, user_id, data_type, data FROM private_infos").
                    WithArgs(1, models.DataTypeLoginPassword).
                    WillReturnRows(rows)
            },
            wantCount: 2,
            wantErr:   false,
        },
        {
            name:     "no data found",
            userID:   1,
            dataType: models.DataTypeLoginPassword,
            mockFunc: func() {
                rows := sqlmock.NewRows([]string{"id", "user_id", "data_type", "data"})
                mock.ExpectQuery("SELECT id, user_id, data_type, data FROM private_infos").
                    WithArgs(1, models.DataTypeLoginPassword).
                    WillReturnRows(rows)
            },
            wantCount: 0,
            wantErr:   false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.mockFunc()

            data, err := storage.ReadData(context.Background(), tt.userID, tt.dataType)

            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Len(t, data, tt.wantCount)
            }
        })
    }
}

func TestUpdateData(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		dataID   int
		data     string
		mockFunc func()
		wantErr  bool
	}{
		{
			name:   "successful update",
			dataID: 1,
			data:   "new data",
			mockFunc: func() {
				mock.ExpectExec("UPDATE private_infos").
					WithArgs("new data", sqlmock.AnyArg(), 1).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name:   "database error",
			dataID: 1,
			data:   "new data",
			mockFunc: func() {
				mock.ExpectExec("UPDATE private_infos").
					WithArgs("new data", sqlmock.AnyArg(), 1).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			err := storage.UpdateData(context.Background(), tt.dataID, tt.data)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeleteData(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		dataID   int
		mockFunc func()
		wantErr  bool
	}{
		{
			name:   "successful deletion",
			dataID: 1,
			mockFunc: func() {
				mock.ExpectExec("DELETE FROM private_infos").
					WithArgs(1).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name:   "database error",
			dataID: 1,
			mockFunc: func() {
				mock.ExpectExec("DELETE FROM private_infos").
					WithArgs(1).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			err := storage.DeleteData(context.Background(), tt.dataID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSaveMasterPassword(t *testing.T) {
    storage, mock, teardown := setupTestDB(t)
    defer teardown()

    tests := []struct {
        name     string
        userID   int
        password string
        mockFunc func()
        wantErr  bool
    }{
        {
            name:     "successful save",
            userID:   1,
            password: "test password",
            mockFunc: func() {
                mock.ExpectExec("UPDATE users").
                    WithArgs("test password", sqlmock.AnyArg(), 1). // добавлен updated_at
                    WillReturnResult(sqlmock.NewResult(1, 1))
            },
            wantErr: false,
        },
        {
            name:     "database error",
            userID:   1,
            password: "test password",
            mockFunc: func() {
                mock.ExpectExec("UPDATE users").
                    WithArgs("test password", sqlmock.AnyArg(), 1). // добавлен updated_at
                    WillReturnError(sql.ErrConnDone)
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.mockFunc()

            err := storage.StoreMasterPassword(context.Background(), tt.userID, tt.password)

            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

func TestCheckMasterPassword(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		userID   int
		mockFunc func()
		wantHash string
		wantErr  bool
	}{
		{
			name:   "successful check",
			userID: 1,
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"master_password_hash"}).
					AddRow("test hash")
				mock.ExpectQuery("SELECT master_password_hash FROM users").
					WithArgs(1).
					WillReturnRows(rows)
			},
			wantHash: "test hash",
			wantErr:  false,
		},
		{
			name:   "no master password",
			userID: 1,
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"master_password_hash"})
				mock.ExpectQuery("SELECT master_password_hash FROM users").
					WithArgs(1).
					WillReturnRows(rows)
			},
			wantHash: "",
			wantErr:  false,
		},
		{
			name:   "database error",
			userID: 1,
			mockFunc: func() {
				mock.ExpectQuery("SELECT master_password_hash FROM users").
					WithArgs(1).
					WillReturnError(sql.ErrConnDone)
			},
			wantHash: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			hash, err := storage.CheckMasterPassword(context.Background(), tt.userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantHash, hash)
			}
		})
	}
}

func TestFindUserByName(t *testing.T) {
    storage, mock, teardown := setupTestDB(t)
    defer teardown()

    tests := []struct {
        name     string
        username string
        mockFunc func()
        wantUser *models.User
        wantErr  bool
    }{
        {
            name:     "successful find",
            username: "testuser",
            mockFunc: func() {
                rows := sqlmock.NewRows([]string{"id", "password_hash"}).
                    AddRow(1, "test hash")
                mock.ExpectQuery("SELECT id, password_hash FROM users WHERE username = \\$1").
                    WithArgs("testuser").
                    WillReturnRows(rows)
            },
            wantUser: &models.User{
                UserID:       1,
                // Username не возвращается из БД в этом запросе
                PasswordHash: "test hash",
            },
            wantErr: false,
        },
        {
            name:     "no user found",
            username: "testuser",
            mockFunc: func() {
                rows := sqlmock.NewRows([]string{"id", "password_hash"})
                mock.ExpectQuery("SELECT id, password_hash FROM users WHERE username = \\$1").
                    WithArgs("testuser").
                    WillReturnRows(rows)
            },
            wantUser: nil,
            wantErr:  false,
        },
        {
            name:     "database error",
            username: "testuser",
            mockFunc: func() {
                mock.ExpectQuery("SELECT id, password_hash FROM users WHERE username = \\$1").
                    WithArgs("testuser").
                    WillReturnError(sql.ErrConnDone)
            },
            wantUser: nil,
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.mockFunc()

            user, err := storage.FindUserByName(context.Background(), tt.username)

            if tt.wantErr {
                assert.Error(t, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                if tt.wantUser == nil {
                    assert.Nil(t, user)
                } else {
                    assert.Equal(t, tt.wantUser, user)
                }
            }

            assert.NoError(t, mock.ExpectationsWereMet())
        })
    }
}

func TestFindUserByID(t *testing.T) {
	storage, mock, teardown := setupTestDB(t)
	defer teardown()

	tests := []struct {
		name     string
		userID   int
		mockFunc func()
		wantUser *models.User
		wantErr  bool
	}{
		{
			name:   "successful find",
			userID: 1,
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"id", "username", "password_hash"}).
					AddRow(1, "testuser", "test hash")
				mock.ExpectQuery("SELECT id, username, password_hash FROM users").
					WithArgs(1).
					WillReturnRows(rows)
			},
			wantUser: &models.User{
				UserID:       1,
				Username:     "testuser",
				PasswordHash: "test hash",
			},
			wantErr: false,
		},
		{
			name:   "no user found",
			userID: 1,
			mockFunc: func() {
				rows := sqlmock.NewRows([]string{"id", "username", "password_hash"})
				mock.ExpectQuery("SELECT id, username, password_hash FROM users").
					WithArgs(1).
					WillReturnRows(rows)
			},
			wantUser: nil,
			wantErr:  false,
		},
		{
			name:   "database error",
			userID: 1,
			mockFunc: func() {
				mock.ExpectQuery("SELECT id, username, password_hash FROM users").
					WithArgs(1).
					WillReturnError(sql.ErrConnDone)
			},
			wantUser: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockFunc()

			user, err := storage.FindUserByID(context.Background(), tt.userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantUser, user)
			}
		})
	}
}