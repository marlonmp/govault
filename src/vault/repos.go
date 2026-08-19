package vault

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
)

var (
	EncVaultNotFoundErr = errors.New("enc valut repo: no enc vault found with the given id")
)

type EncVaultRepo interface {
	CreateByUserID(ctx context.Context, userID uuid.UUID, eVault *encVault) error
	AddUserByIDs(ctx context.Context, userID uuid.UUID, eVaultID uuid.UUID) error
	UpdateByID(ctx context.Context, id uuid.UUID, eVault *encVault) error
	DeleteByID(ctx context.Context, id uuid.UUID) error
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*encVault, error)
}

type pgEncVaultRepo struct {
	conn   *sql.Conn
	logger *slog.Logger
}

func (repo *pgEncVaultRepo) CreateByUserID(ctx context.Context, userID uuid.UUID, eVault *encVault) error {
	query := `
	insert into vaults ("user_id", "title", "key", "content")
		values ($1, $2, $3, $4)
		returning "vault_id", "created_at", "updated_at"`
	return repo.conn.
		QueryRowContext(ctx, query, userID, eVault.Title, eVault.Key, eVault.Content).
		Scan(&eVault.ID, &eVault.CreatedAt, &eVault.UpdatedAt)
}


func (repo *pgEncVaultRepo) AddUserByIDs(ctx context.Context, userID uuid.UUID, eVaultID uuid.UUID) error {
	query := `
	insert into vaults_allowed_users ("user_id", "vault_id")
		values ($1, $2)
		returning id`
	_, err := repo.conn.ExecContext(ctx, query, userID, eVaultID)
	if err != nil {
		return err
	}
	return nil
}

func (repo *pgEncVaultRepo) UpdateByID(ctx context.Context, id uuid.UUID, eVault *encVault) error {
	query := `
	update vaults
		set "title" = $2, "key" = $3, "content" = $4, "updated_at" = now()
		where "vault_id" = $1
		returning "updated_at"`
	err := repo.conn.
		QueryRowContext(ctx, query, id, eVault.Title, eVault.Key, eVault.Content).
		Scan(&eVault.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EncVaultNotFoundErr
	}
	return err
}

func (repo *pgEncVaultRepo) DeleteByID(ctx context.Context, id uuid.UUID) error {
	query := `delete from vaults where "vault_id" = $1`
	res, err := repo.conn.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return EncVaultNotFoundErr
	}
	return nil
}

func (repo *pgEncVaultRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*encVault, error) {
	query := `
		select v."vault_id", v."title", v."key", v."content", coalesce(vau."sync_allowed", true), v."created_at", v."updated_at"
		from vaults v join vaults_allowed_users vau on v."vault_id" = vau."vault_id"
		where v."user_id" = $1 or vau.vault_id = $1`
		rows, err := repo.conn.QueryContext(ctx, query, userID)
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
