package user

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

type UserRepo interface {
	CreateOne(ctx context.Context, user User) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	UpdateByID(ctx context.Context, id uuid.UUID, user User) (User, error)
}

type pgUserRepo struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPGUserRepo(db *sql.DB, logger *slog.Logger) UserRepo {
	return &pgUserRepo{db: db, logger: logger}
}

func (repo *pgUserRepo) CreateOne(ctx context.Context, user User) (User, error) {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	insert into users (nickname, email)
		values ($1, $2)
		returning user_id, created_at, updated_at`
	err := qa.
		QueryRowContext(ctx, query, user.Nickname, user.Email).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	// if unique conflict, it means the email is already used
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ColumnName != "email" {
			return User{}, err
		}
		return User{}, errs.ConflictError("an user with this email already exists, please enter another email", err)
	}
	return user, err
}

func (repo *pgUserRepo) GetByEmail(ctx context.Context, email string) (User, error) {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	user := User{}
	query := `
	select user_id, nickname, email, created_at, updated_at
		from users where email = $1`
	err := qa.
		QueryRowContext(ctx, query, email).
		Scan(&user.ID, &user.Nickname, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	// if no rows the user does not exists
	if errors.Is(err, sql.ErrNoRows) {
		return user, errs.NotFoundError("user with this email does not exist")
	}
	return user, err
}

func (repo *pgUserRepo) UpdateByID(ctx context.Context, id uuid.UUID, user User) (User, error) {
	qa := repos.GetSqlQueryAbleFromContext(ctx, repo.db)
	query := `
	update users
		set nickname = $2, email = $3, updated_at = now()
		where user_id = $1 returning updated_at`
	err := qa.
		QueryRowContext(ctx, query, id, user.Nickname, user.Email).
		Scan(&user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, errs.NotFoundError("user with this uuid does not exist")
	}
	// if there is a unique conflict in the update it means the email is already used
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ColumnName != "email" {
			return User{}, err
		}
		return User{}, errs.ConflictError("an user with this email already exists, please enter another email", err)
	}
	return user, err
}
