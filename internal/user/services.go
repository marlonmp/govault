package user

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

type userService struct {
	users  UserRepo
	logger *slog.Logger
}

func NewUserService(userRepo UserRepo, logger *slog.Logger) userService {
	return userService{users: userRepo, logger: logger}
}

func (us userService) SignUp(ctx context.Context, payload RegisterUserPayload) (User, error) {
	err := payload.Validate()
	if err != nil {
		return User{}, err
	}
	user := payload.Build()
	user, err = us.users.CreateOne(ctx, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (us userService) VerifyByEmail(ctx context.Context, payload VerifyEmailPayload) error {
	err := payload.Validate()
	if err != nil {
		return err
	}
	// TODO: implement email validations
	return nil
}

func (us userService) UpdateUserByID(ctx context.Context, id uuid.UUID, payload UpdateUserPayload) (User, error) {
	err := payload.Validate()
	if err != nil {
		return User{}, err
	}
	user := payload.Build()
	user, err = us.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (us userService) ChangeEmailByID(ctx context.Context, id uuid.UUID, payload ChangeEmailPayload) (User, error) {
	err := payload.Validate()
	if err != nil {
		return User{}, err
	}
	user := payload.Build()
	user, err = us.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}
