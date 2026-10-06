package crypto

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marlonmp/govault/internal/errs"
)

type EncKeysetRepo interface {
	CreateByUserID(ctx context.Context, userID uuid.UUID, keyset *EncKeyset) (*EncKeyset, error)
	GetByUserEmail(ctx context.Context, email string) (*EncKeyset, error)
	UpdateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *EncKeyset) error
}

type pgEncKeysetRepo struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPGEcnKeyset(db *sql.DB, logger *slog.Logger) EncKeysetRepo {
	return &pgEncKeysetRepo{db: db, logger: logger}
}

func (repo *pgEncKeysetRepo) CreateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *EncKeyset) (*EncKeyset, error) {
	query := `
	insert into keysets (user_id, auth_salt, enc_salt, srp_verifier, pub_key, enc_priv_key)
		values ($1, $2, $3, $4, $5, $6)
		returning keyset_id, created_at, updated_at`
	err := repo.db.
		QueryRowContext(ctx, query, userID, encKeyset.AuthSalt, encKeyset.EncSalt, encKeyset.SRPVerifier, encKeyset.PubKey, encKeyset.EncPrivKey).
		Scan(&encKeyset.ID, &encKeyset.CreatedAt, &encKeyset.UpdatedAt)
	// if unique conflict, it means the keyset already exist for the user
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ColumnName != "email" {
			return nil, errs.UnknownError(err)
		}
		return nil, errs.ConflictError("a keyset already exists for this user", err)
	}
	if err != nil {
		return nil, errs.UnknownError(err)
	}
	return encKeyset, nil
}

func (repo *pgEncKeysetRepo) GetByUserEmail(ctx context.Context, email string) (*EncKeyset, error) {
	ek := &EncKeyset{}
	query := `
	select k.keyset_id, k.auth_salt, k.enc_salt, k.srp_verifier, k.pub_key, k.enc_priv_key, k.created_at, k.updated_at
		from keysets k
		inner join users u on k.user_id = u.user_id
		where u.email = $1`
	err := repo.db.
		QueryRowContext(ctx, query, email).
		Scan(&ek.ID, &ek.AuthSalt, &ek.EncSalt, &ek.SRPVerifier, &ek.PubKey, &ek.EncPrivKey, &ek.CreatedAt, &ek.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errs.NotFoundError("keyset for this user does not exist")
	}
	return ek, err
}

func (repo *pgEncKeysetRepo) UpdateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *EncKeyset) error {
	query := `
	update keysets
		set auth_salt = $2, enc_salt = $3, srp_verifier = $4, pub_key = $5, enc_priv_key = $6, updated_at = now()
		where user_id = $1
		returning updated_at`
	err := repo.db.
		QueryRowContext(ctx, query, userID, encKeyset.AuthSalt, encKeyset.EncSalt, encKeyset, encKeyset.SRPVerifier, encKeyset.PubKey, encKeyset.EncPrivKey).
		Scan(&encKeyset.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return errs.NotFoundError("keyset for this user does not exist")
	}
	if err != nil {
		return errs.UnknownError(err)
	}
	return nil
}
