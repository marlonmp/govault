package vault

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/marlonmp/govault/pkg/repos"
)

var (
	EncVaultNotFoundErr = errors.New("enc valut repo: no enc vault found with the given id")
)

type EncVaultRepo interface {
	CreateByUserID(ctx context.Context, userID uuid.UUID, eVault *encVault) (*encVault, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*encVault, error)
	UpdateByID(ctx context.Context, id uuid.UUID, eVault *encVault) error
	DeleteByID(ctx context.Context, id uuid.UUID) error

	AppendUserIDByID(ctx context.Context, userID uuid.UUID, vaultID uuid.UUID, encKey string, canSync bool) error
	RemoveUserIDByID(ctx context.Context, userID uuid.UUID, vaultID uuid.UUID) error
}

type pgEncVaultRepo struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPgEncVaultRepo(db *sql.DB, logger *slog.Logger) EncVaultRepo {
	return &pgEncVaultRepo{db: db, logger: logger}
}

func (repo *pgEncVaultRepo) CreateByUserID(ctx context.Context, userID uuid.UUID, eVault *encVault) (*encVault, error) {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	insert into vaults (user_id, title, content)
		values ($1, $2, $3)
		returning vault_id, created_at, updated_at`
	err := qa.
		QueryRowContext(ctx, query, userID, eVault.Title, eVault.Content).
		Scan(&eVault.ID, &eVault.CreatedAt, &eVault.UpdatedAt)
	return eVault, err
}

func (repo *pgEncVaultRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*encVault, error) {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	select v.vault_id, v.title, vau.key, v.content, vau.sync_allowed, v.created_at, v.updated_at
		from vaults v
		inner join vaults_allowed_users vau on v.vault_id = vau.vault_id
		where vau.vault_id = $1`
	rows, err := qa.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	encVaults := make([]*encVault, 0)
	for rows.Next() {
		ev := &encVault{}
		err = rows.Scan(&ev.ID, &ev.Title, &ev.Key, &ev.Content, &ev.CanSync, &ev.CreatedAt, &ev.UpdatedAt)
		if err != nil {
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return encVaults, nil
}

func (repo *pgEncVaultRepo) UpdateByID(ctx context.Context, id uuid.UUID, eVault *encVault) error {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	update vaults
		set title = $2, key = $3, content = $4, updated_at = now()
		where vault_id = $1
		returning updated_at`
	err := qa.
		QueryRowContext(ctx, query, id, eVault.Title, eVault.Key, eVault.Content).
		Scan(&eVault.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return errs.NotFoundError("vault with the given id does not exist")
	}
	return err
}

func (repo *pgEncVaultRepo) DeleteByID(ctx context.Context, id uuid.UUID) error {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	delete from vaults
		where "vault_id" = $1`
	res, err := qa.ExecContext(ctx, query, id)
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

func (repo *pgEncVaultRepo) AppendUserIDByID(ctx context.Context, userID uuid.UUID, vaultID uuid.UUID, encKey string, canSync bool) error {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	insert into vaults_allowed_users (user_id, vault_id, enc_key, can_sync)
		values ($1, $2, $3, $4)
		returning id`
	_, err := qa.ExecContext(ctx, query, userID, vaultID, encKey, canSync)
	// if unique conflict, it means a vault allowed user already exist
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return errs.ConflictError("vault for this user already exist", err)
	}
	return err
}

func (repo *pgEncVaultRepo) RemoveUserIDByID(ctx context.Context, userID uuid.UUID, vaultID uuid.UUID) error {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
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
