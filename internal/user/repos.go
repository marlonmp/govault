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
	UserNotFoundByEmailErr  = errors.New("user repo: no user found with the given email")
	UserEmailAlreadyUsedErr = errors.New("user repo: cannot create user, email already used")
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
	query := `
	insert into users (nickname, email)
		values ($1, $2)
		returning user_id, created_at, updated_at`
	err := repo.db.
		QueryRowContext(ctx, query, user.Nickname, user.Email).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	// if unique conflict, it means the emal is already used
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return User{}, UserEmailAlreadyUsedErr
	}
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (repo *pgUserRepo) GetByEmail(ctx context.Context, email string) (User, error) {
	user := User{}
	query := `
	select user_id, nickname, email, created_at, updated_at
		from users where email = $1`
	err := repo.db.
		QueryRowContext(ctx, query, email).
		Scan(&user.ID, &user.Nickname, &user.Email, &user.CreatedAt, &user.UpdatedAt)
	// if no rows the user does not exists
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, UserNotFoundByEmailErr
	}
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (repo *pgUserRepo) UpdateByID(ctx context.Context, id uuid.UUID, user User) (User, error) {
	query := `
	update users
		set nickname = $2, email = $3, updated_at = now()
		where user_id = $1 returning updated_at`
	err := repo.db.
		QueryRowContext(ctx, query, id, user.Nickname, user.Email).
		Scan(&user.UpdatedAt)
	// if there is a unique conflict in the update it means the email is already used
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return User{}, UserEmailAlreadyUsedErr
	}
	if err != nil {
		return User{}, err
	}
	return user, nil
}
