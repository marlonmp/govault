package keyset

import (
	"context"
	"log/slog"
)

type encKeysetService struct {
	keysets EncKeysetRepo
	logger  *slog.Logger
}

func EncKeysetService(keysets EncKeysetRepo, logger *slog.Logger) *encKeysetService {
	return &encKeysetService{keysets: keysets, logger: logger}
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
