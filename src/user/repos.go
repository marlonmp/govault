package user

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	UserNotFoundErr         = errors.New("user repo: no user found with the given id")
	UserEmailAlreadyUsedErr = errors.New("user repo: cannot create user, emal already used")
)

type UserRepo interface {
	Create(ctx context.Context, user User) (User, error)
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	UpdateByID(ctx context.Context, id uuid.UUID, user User) (User, error)
}

type pgUserRepo struct {
	conn   *sql.Conn
	logger *slog.Logger
}

func NewPGUserRepo(conn *sql.Conn, logger *slog.Logger) UserRepo {
	return &pgUserRepo{conn: conn, logger: logger}
}

func (repo *pgUserRepo) Create(ctx context.Context, user User) (User, error) {
	query := `insert into users ("nickname", "email") values ($1, $2) returning "id", "created_at", "updated_at"`
	err := repo.conn.
		QueryRowContext(ctx, query, user.Nickname, user.Email).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return user, UserEmailAlreadyUsedErr
	}
	return user, err
}

func (repo *pgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (User, error) {
	user := User{}
	query := `select "id", "nickname", "email", "created_at", "updated_at" from users where "id" = $1`
	err := repo.conn.
		QueryRowContext(ctx, query, id).
		Scan(&user.ID, &user.Nickname, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return user, UserNotFoundErr
	}
	return user, err
}

func (repo *pgUserRepo) UpdateByID(ctx context.Context, id uuid.UUID, user User) (User, error) {
	query := `update users set "nickname" = $2, "email" = $3, "updated_at" = now() where "id" = $1" returning "updated_at"`
	err := repo.conn.
		QueryRowContext(ctx, query, id, user.Nickname, user.Email).
		Scan(&user.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return user, UserEmailAlreadyUsedErr
	}
	return user, err
}

