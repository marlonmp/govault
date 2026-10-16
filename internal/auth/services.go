package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/pkg/db"
)

type userService struct {
	users  UserRepo
	emails EmailVerificationRepo
	dbh    db.Handler
	logger *slog.Logger
}

func NewUserService(users UserRepo, emails EmailVerificationRepo, dbh db.Handler, logger *slog.Logger) *userService {
	return &userService{users: users, emails: emails, dbh: dbh, logger: logger}
}

func (serv userService) SignUp(ctx context.Context, payload RegisterUserPayload) (User, error) {
	err := payload.Validate()
	if err != nil {
		return User{}, err
	}
	user := payload.Build()
	user, err = serv.users.CreateOne(ctx, user)
	if err != nil {
		return User{}, err
	}
	otp := NewEmailOTP(user.ID, user.Email)
	_, err = serv.emails.TempCreateEmailOTP(ctx, otp, 10*time.Second)
	if err != nil {
		return user, err
	}
	return user, nil
}

func (serv userService) VerifyByEmail(ctx context.Context, payload VerifyEmailPayload) error {
	err := payload.Validate()
	if err != nil {
		return err
	}
	otp, err := serv.emails.GetEmailOTPByEmail(ctx, payload.Email)
	if err != nil {
		return err
	}
	_, err = serv.emails.CreateByEmailOTP(ctx, otp)
	return err
}

func (serv userService) UpdateUserByID(ctx context.Context, id uuid.UUID, payload UpdateUserPayload) (User, error) {
	err := payload.Validate()
	if err != nil {
		return User{}, err
	}
	user := payload.Build()
	user, err = serv.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (serv userService) ChangeEmailByID(ctx context.Context, id uuid.UUID, payload ChangeEmailPayload) (User, error) {
	err := payload.Validate()
	if err != nil {
		return User{}, err
	}
	user := payload.Build()
	user, err = serv.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	otp := NewEmailOTP(user.ID, user.Email)
	_, err = serv.emails.TempCreateEmailOTP(ctx, otp, 10*time.Second)
	if err != nil {
		return user, err
	}
	return user, nil
}
