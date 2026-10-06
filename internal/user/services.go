package user

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

type userService struct {
	users UserRepo
	logger   *slog.Logger
}

func NewUserService(userRepo UserRepo, logger *slog.Logger) userService {
	return userService{users: userRepo, logger: logger}
}

func (us userService) CreateUser(ctx context.Context, payload RegisterUserPayload) (User, error) {
	err := payload.GetValidationError()
	if err != nil {
		return User{}, err
	}
	user := payload.BuildUser()
	user, err = us.users.CreateOne(ctx, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (us userService) UpdateUser(ctx context.Context, id uuid.UUID, payload RegisterUserPayload) (User, error) {
	err := payload.GetValidationError()
	if err != nil {
		return User{}, err
	}
	user := payload.BuildUser()
	user, err = us.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}
