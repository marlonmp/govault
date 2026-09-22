package user

import (
	"context"
	"log/slog"
)

type userService struct {
	userRepo UserRepo
	logger   *slog.Logger
}

func NewUserService(userRepo UserRepo, logger *slog.Logger) userService {
	return userService{userRepo: userRepo, logger: logger}
}

func (us userService) CreateUser(ctx context.Context, user User) {
}
