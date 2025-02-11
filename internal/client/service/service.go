package service

import (
	"context"

	"github.com/vova4o/gokeeper2/package/logger"
)

// Service struct
type Service struct {
	stor   Storager
	logger *logger.Logger
}

// Storager interface
type Storager interface {
	AddOrReplaceRefreshToken(ctx context.Context, data string) error
	GetRefreshToken(ctx context.Context) (string, error)
}

// NewService creates new service instance
func NewService(stor Storager, logger *logger.Logger) *Service {
	return &Service{
		stor:   stor,
		logger: logger,
	}
}

// AddOrReplaceRefreshToken adds refresh token to storage
func (s *Service) AddOrReplaceRefreshToken(ctx context.Context, data string) error {
	s.logger.Info("Adding refresh token to storage")

	err := s.stor.AddOrReplaceRefreshToken(ctx, data)
	if err != nil {
		s.logger.Error("Failed to add refresh token to storage")
		return err
	}

	return nil
}

// GetRefreshToken reads refresh tokens from storage
func (s *Service) GetRefreshToken(ctx context.Context) (string, error) {
	s.logger.Info("Reading refresh tokens from storage")

	token, err := s.stor.GetRefreshToken(ctx)
	if err != nil {
		s.logger.Error("Failed to read refresh tokens from storage")
		return "", err
	}

	return token, nil
}
