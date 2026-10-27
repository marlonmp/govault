package keyset

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marlonmp/govault/pkg/db"
	"github.com/marlonmp/govault/pkg/errs"
)

type KeysetRepo interface {
	CreateByUserID(ctx context.Context, userID uuid.UUID, keyset *Keyset) (*Keyset, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*Keyset, error)
	UpdateByUserID(ctx context.Context, userID uuid.UUID, encKeyset *Keyset) (*Keyset, error)
}

type pgKeysetRepo struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPGKeyset(db *sql.DB, logger *slog.Logger) KeysetRepo {
	return &pgKeysetRepo{db: db, logger: logger}
}

func (repo *pgKeysetRepo) CreateByUserID(ctx context.Context, userID uuid.UUID, keyset *Keyset) (*Keyset, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	insert into keysets (user_id, data)
		values ($1, $2)
		returning keyset_id, created_at, updated_at`
	err := qa.
		QueryRowContext(ctx, query, userID, keyset).
		Scan(&keyset.ID, &keyset.CreatedAt, &keyset.UpdatedAt)
	// if unique conflict, it means the keyset already exist for the user
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ColumnName != "email" {
			return nil, err
		}
		return nil, errs.ConflictError("a keyset already exists for this user", err)
	}
	return keyset, err
}

func (repo *pgKeysetRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*Keyset, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	keyset := &Keyset{}
	query := `
	select k.keyset_id, k.sequence_number, k.data, k.created_at, k.updated_at
		from keysets k
		inner join users u on k.user_id = u.user_id
		where u.email = $1 order by k.sequence_number limit 1`
	err := qa.
		QueryRowContext(ctx, query, userID).
		Scan(&keyset.ID, &keyset.SequenceNumber, &keyset, &keyset.CreatedAt, &keyset.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errs.NotFoundError("keyset for this user does not exist")
	}
	return keyset, err
}

func (repo *pgKeysetRepo) UpdateByUserID(ctx context.Context, userID uuid.UUID, keyset *Keyset) (*Keyset, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	update keysets
		set data = $2, sequence_number = sequence_number + 1, updated_at = now()
		where user_id = $1
		returning updated_at`
	err := qa.
		QueryRowContext(ctx, query, userID, keyset).
		Scan(&keyset.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errs.NotFoundError("keyset for this user does not exist")
	}
	return keyset, nil
}
