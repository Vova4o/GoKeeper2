package storage

import (
	"context"
	"database/sql"
	"fmt"

	// SQLite driver
	_ "github.com/mattn/go-sqlite3"
	"github.com/vova4o/gokeeper2/package/logger"
)

// Storage struct for storage
type Storage struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewStorage создает новое хранилище и инициализирует базу данных SQLite
func NewStorage(dbPath string, logger *logger.Logger) (*Storage, error) {
	if dbPath == "" {
		dbPath = "keeper.db"
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %v", err)
	}

	storage := &Storage{
		db:     db,
		logger: logger,
	}

	// Создание таблицы для хранения данных
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token TEXT,
		create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
    `
	_, err = storage.db.Exec(createTableQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %v", err)
	}

	logger.Info("SQLite database initialized successfully")
	return storage, nil
}

// AddOrReplaceRefreshToken добавляет или обновляет токен обновления в базе данных
func (s *Storage) AddOrReplaceRefreshToken(ctx context.Context, data string) error {
	// Проверка наличия токена в базе данных
	var existingToken string
	err := s.db.QueryRowContext(ctx, "SELECT token FROM refresh_tokens LIMIT 1").Scan(&existingToken)
	if err != nil && err != sql.ErrNoRows {
		s.logger.Error("Failed to check existing refresh token: " + err.Error())
		return err
	}

	if existingToken != "" {
		// Обновление существующего токена
		updateQuery := `UPDATE refresh_tokens SET token = ? WHERE token = ?`
		_, err := s.db.ExecContext(ctx, updateQuery, data, existingToken)
		if err != nil {
			s.logger.Error("Failed to update refresh token: " + err.Error())
			return err
		}
		s.logger.Info("Refresh token updated successfully")
	} else {
		// Добавление нового токена
		insertQuery := `INSERT INTO refresh_tokens (token) VALUES (?)`
		_, err := s.db.ExecContext(ctx, insertQuery, data)
		if err != nil {
			s.logger.Error("Failed to insert refresh token: " + err.Error())
			return err
		}
		s.logger.Info("Refresh token added successfully")
	}

	return nil
}

// GetRefreshToken читает последний токен обновления из базы данных
func (s *Storage) GetRefreshToken(ctx context.Context) (string, error) {
	var token string
	err := s.db.QueryRowContext(ctx, "SELECT token FROM refresh_tokens LIMIT 1").Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			s.logger.Info("No refresh tokens found")
			return "", nil
		}
		s.logger.Error("Failed to read refresh token: " + err.Error())
		return "", err
	}

	s.logger.Info("Latest refresh token read successfully")
	return token, nil
}
