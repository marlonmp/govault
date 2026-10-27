package keyset

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/pkg/crypto"
)

type encKeysetService struct {
	keysets KeysetRepo
	// TODO: resolve impont cycle
	// sessions auth.SessionRepo
	logger *slog.Logger
}

func EncKeysetService(keysets KeysetRepo, logger *slog.Logger) *encKeysetService {
	return &encKeysetService{keysets: keysets, logger: logger}
}

func (eks encKeysetService) GetBySessionID(ctx context.Context, sid uuid.UUID) (*crypto.JWE, error) {
	return nil, nil
}

func (eks encKeysetService) UpdateBySessionID(ctx context.Context, sid uuid.UUID) (*crypto.JWE, error) {
	return nil, nil
}
