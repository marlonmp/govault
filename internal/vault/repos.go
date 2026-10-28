package vault

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marlonmp/govault/pkg/crypto"
	"github.com/marlonmp/govault/pkg/db"
	"github.com/marlonmp/govault/pkg/errs"
)

var (
	EncVaultNotFoundErr = errors.New("enc valut repo: no enc vault found with the given id")
)

type EncVaultRepo interface {
	CreateByUserID(ctx context.Context, vault *EncVault, userID uuid.UUID) (*EncVault, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*EncVault, error)
	UpdateByID(ctx context.Context, vaultID uuid.UUID, vault *EncVault) error
	DeleteByID(ctx context.Context, vaultID uuid.UUID) error

	AppendUserByID(ctx context.Context, vaultID, userID uuid.UUID, encSymKey *crypto.JWE, IsReadOnly bool) error
	RemoveUserByID(ctx context.Context, vaultID, userID uuid.UUID) error
}

type pgEncVaultRepo struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPgEncVaultRepo(db *sql.DB, logger *slog.Logger) EncVaultRepo {
	return &pgEncVaultRepo{db: db, logger: logger}
}

func (repo *pgEncVaultRepo) CreateByUserID(ctx context.Context, vault *EncVault, userID uuid.UUID) (*EncVault, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	insert into vaults (created_by_id, data)
		values ($1, $2)
		returning enc_vault_id, sequence_number, created_at, updated_at`
	err := qa.
		QueryRowContext(ctx, query, userID, vault.Data).
		Scan(&vault.ID, &vault.SequenceNumber, &vault.CreatedAt, &vault.UpdatedAt)
	return vault, err
}

func (repo *pgEncVaultRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*EncVault, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	select v.enc_vault_id, v.sequence_number, v.data, evu.enc_sym_key, evu.is_read_only, v.created_at, v.updated_at
		from vaults v
		inner join enc_vault_user evu on v.enc_vault_id = evu.enc_vault_id
		where evu.user_id = $1`
	rows, err := qa.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	vaults := make([]*EncVault, 0)
	for rows.Next() {
		v := &EncVault{}
		err = rows.Scan(&v.ID, &v.SequenceNumber, &v.Data, &v.EncSymKey, &v.IsReadOnly, &v.CreatedAt, &v.UpdatedAt)
		if err != nil {
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return vaults, nil
}

func (repo *pgEncVaultRepo) UpdateByID(ctx context.Context, vaultID uuid.UUID, vault *EncVault) error {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	update vaults
		set data = $2, sequence_number = sequence_number + 1, updated_at = now()
		where vault_id = $1
		returning updated_at`
	err := qa.
		QueryRowContext(ctx, query, vaultID, vault.Data).
		Scan(&vault.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return errs.NotFoundError("vault with the given id does not exist")
	}
	return err
}

func (repo *pgEncVaultRepo) DeleteByID(ctx context.Context, vaultID uuid.UUID) error {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	delete from vaults
		where "vault_id" = $1`
	res, err := qa.ExecContext(ctx, query, vaultID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.NotFoundError("vault with the given id does not exist")
	}
	return nil
}

func (repo *pgEncVaultRepo) AppendUserByID(ctx context.Context, vaultID, userID uuid.UUID, encSymKey *crypto.JWE, IsReadOnly bool) error {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	insert into vaults_allowed_users (enc_vault_id, user_id, enc_sym_key, is_read_only)
		values ($1, $2, $3, $4)
		returning id`
	_, err := qa.ExecContext(ctx, query, vaultID, userID, encSymKey, IsReadOnly)
	// if unique conflict, it means a vault allowed user already exist
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return errs.ConflictError("vault for this user already exist", err)
	}
	return err
}

func (repo *pgEncVaultRepo) RemoveUserByID(ctx context.Context, vaultID, userID uuid.UUID) error {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	delete from vaults_allowed_users
		where user_id = $1 and vault_id = $2`
	res, err := qa.ExecContext(ctx, query, userID, vaultID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.NotFoundError("vault with the given id does not exist")
	}
	return nil
}
