package user

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/pkg/db"
)

type accountService struct {
	users  UserRepo
	emails EmailVerificationRepo
	dbh    db.Handler
	logger *slog.Logger
}

func NewAccountService(users UserRepo, emails EmailVerificationRepo, dbh db.Handler, logger *slog.Logger) accountService {
	return accountService{users: users, emails: emails, dbh: dbh, logger: logger}
}

func (serv accountService) SignUp(ctx context.Context, payload RegisterUserPayload) (User, error) {
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

func (serv accountService) VerifyByEmail(ctx context.Context, payload VerifyEmailPayload) error {
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

func (serv accountService) UpdateUserByID(ctx context.Context, id uuid.UUID, payload UpdateUserPayload) (User, error) {
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

func (serv accountService) ChangeEmailByID(ctx context.Context, id uuid.UUID, payload ChangeEmailPayload) (User, error) {
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
