package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/marlonmp/govault/pkg/db"
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/redis/go-redis/v9"
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
	qa := db.QueryableFromContext(ctx, repo.db)
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
	qa := db.QueryableFromContext(ctx, repo.db)
	user := User{}
	query := `
	select user_id, nickname, email, secret_key, auth, created_at, updated_at
		from users where email = $1`
	err := qa.
		QueryRowContext(ctx, query, email).
		Scan(&user.ID, &user.Nickname, &user.Email, &user.SecretKey, &user.Auth, &user.CreatedAt, &user.UpdatedAt)
	// if no rows the user does not exists
	if errors.Is(err, sql.ErrNoRows) {
		return user, errs.NotFoundError("user with this email does not exist")
	}
	return user, err
}

func (repo *pgUserRepo) UpdateByID(ctx context.Context, id uuid.UUID, user User) (User, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	query := `
	update users
		set nickname = coalesce($2, nickname), email = coalesce($3, email),
		secret_key = cealesce($4, secret_key), auth = coalesce($5, auth), updated_at = now()
		where user_id = $1 returning updated_at`
	err := qa.
		QueryRowContext(ctx, query, id, user.Nickname, user.Email, user.SecretKey, user.Auth).
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

type EmailVerificationRepo interface {
	TempCreateEmailOTP(ctx context.Context, otp EmailOTP, ttl time.Duration) (bool, error)
	GetEmailOTPByEmail(ctx context.Context, email string) (EmailOTP, error)
	CreateByEmailOTP(ctx context.Context, otp EmailOTP) (EmailVerification, error)
}

type pgEmailVerificationRepo struct {
	db     *sql.DB
	cache *redis.Client
	logger *slog.Logger
}

func NewEmailVerificationRepo(db *sql.DB, cache *redis.Client, logger *slog.Logger) EmailVerificationRepo {
	return &pgEmailVerificationRepo{db: db, cache: cache, logger: logger}
}

func (repo *pgEmailVerificationRepo) TempCreateEmailOTP(ctx context.Context, otp EmailOTP, ttl time.Duration) (bool, error) {
	key := fmt.Sprintf("EMAIL_OTPS:%s", otp.Email)
	value, err := json.Marshal(otp)
	if err != nil {
		return false, err
	}
	return repo.cache.SetNX(ctx, key, string(value), ttl).Result()
}

func (repo *pgEmailVerificationRepo) GetEmailOTPByEmail(ctx context.Context, email string) (EmailOTP, error) {
	key := fmt.Sprintf("EMAIL_OTPS:%s", email)
	data, err := repo.cache.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return EmailOTP{}, errs.NotFoundError("no OTP found for this email")
	}
	if err != nil {
		return EmailOTP{}, err
	}
	var otp EmailOTP
	err = json.Unmarshal([]byte(data), &otp)
	if err != nil {
		return EmailOTP{}, err
	}
	d, err := repo.cache.TTL(ctx, key).Result()
	if err != nil {
		return EmailOTP{}, err
	}
	otp.SetExpiresAt(d)
	return otp, nil
}

func (repo *pgEmailVerificationRepo) CreateByEmailOTP(ctx context.Context, otp EmailOTP) (EmailVerification, error) {
	qa := db.QueryableFromContext(ctx, repo.db)
	verification := NewEmailVerificationFromOTP(otp)
	query := `
	insert into email_verification (user_id, email)
		values ($1, $2) returning verification_id, created_at`
	err := qa.
		QueryRowContext(ctx, query, otp.UserID, otp.Email).
		Scan(&verification.ID, &verification.CreatedAt)
	return verification, err
}
