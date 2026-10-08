package crypto

import (
	"context"
	"log/slog"

	"github.com/marlonmp/govault/internal/user"
)

type encKeysetService struct {
	keysets EncKeysetRepo
	users   user.UserRepo
	logger  *slog.Logger
}

func EncKeysetService(keysets EncKeysetRepo, users user.UserRepo, logger *slog.Logger) *encKeysetService {
	return &encKeysetService{keysets: keysets, users: users, logger: logger}
}

func (eks encKeysetService) CreateEncKeysetByUserEmail(ctx context.Context) error {
	return nil
}

func (eks encKeysetService) Start(ctx context.Context) error {
	return nil
}

func (eks encKeysetService) Auth(ctx context.Context) error {
	return nil
}

func (eks encKeysetService) ConfirmKey(ctx context.Context) error {
	return nil
}

func (eks encKeysetService) Complete(ctx context.Context) error {
	return nil
}
