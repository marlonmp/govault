package crypto

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
)

var (
	UserEncKeysetNotFoundErr = errors.New("enc keyset repo: no enc keyset found with the given user id")
)

type EncKeysetRepo interface {
	CreateByUserID(ctx context.Context, userID uuid.UUID, keyset *EncKeyset) error
	GetByUserID(ctx context.Context, userID uuid.UUID) (*EncKeyset, error)
	UpdateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *EncKeyset) error
}

type pgEncKeysetRepo struct {
	conn   *sql.Conn
	logger *slog.Logger
}

func NewPGEcnKeyset(conn *sql.Conn, logger *slog.Logger) EncKeysetRepo {
	return &pgEncKeysetRepo{conn: conn, logger: logger}
}

func (repo *pgEncKeysetRepo) CreateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *EncKeyset) error {
	query := `
	insert into keysets ("user_id", "auth_salt", "enc_salt", "srp_verifier", "pub_key", "enc_priv_key")
		values ($1, $2, $3, $4, $5, $6)
		returning "keyset_id", "created_at", "updated_at"`
	return repo.conn.
		QueryRowContext(ctx, query, userID, encKeyset.AuthSalt, encKeyset.EncSalt, encKeyset.SRPVerifier, encKeyset.PubKey, encKeyset.EncPrivKey).
		Scan(&encKeyset.ID, &encKeyset.CreatedAt, &encKeyset.UpdatedAt)
}

func (repo *pgEncKeysetRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*EncKeyset, error) {
	ek := &EncKeyset{}
	query := `
	select "keyset_id", "auth_salt", "enc_salt", "srp_verifier", "pub_key", "enc_priv_key", "created_at", "updated_at"
		from keysets where "user_id" = $1`
	err := repo.conn.
		QueryRowContext(ctx, query, userID).
		Scan(&ek.ID, &ek.AuthSalt, &ek.EncSalt, &ek.SRPVerifier, &ek.PubKey, &ek.EncPrivKey, &ek.CreatedAt, &ek.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ek, UserEncKeysetNotFoundErr
	}
	return ek, err
}

func (repo *pgEncKeysetRepo) UpdateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *EncKeyset) error {
	query := `
	update keysets
		set "auth_salt" = $2, "enc_salt" = $3, "srp_verifier" = $4, "pub_key" = $5, "enc_priv_key" = $6, "updated_at" = now()
		where "user_id" = $1
		returning "updated_at"`
	err := repo.conn.
		QueryRowContext(ctx, query, userID, encKeyset.AuthSalt, encKeyset.EncSalt, encKeyset, encKeyset.SRPVerifier, encKeyset.PubKey, encKeyset.EncPrivKey).
		Scan(&encKeyset.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return UserEncKeysetNotFoundErr
	}
	return err
}
