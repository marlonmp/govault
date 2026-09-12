package user

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/marlonmp/govault/pkg/val"
)

type userService struct {
	userRepo UserRepo
	logger   *slog.Logger
}

type RegisterUserRequest struct {
	Nickname string
	Email    string
}

func (rur *RegisterUserRequest) validate() error {
	val.NewSchema(val.S{
		"nickname": val.String().ValRef(&rur.Nickname).Trim().Min(3).Max(32),
		"email":    val.String().ValRef(&rur.Email).StrictEmail(),
	}).RefChekcAll()
	return nil
}

func NewUserService(userRepo UserRepo, logger *slog.Logger) userService {
	return userService{userRepo: userRepo, logger: logger}
}

func (us userService) userValidations(ctx context.Context, user User) (User, error) {
	user.Nickname = strings.TrimSpace(user.Nickname)
	if len(user.Nickname) < 3 {
		return User{}, errors.New("user service: user nick name too short: min allowed 3 characters")
	}
	if len(user.Nickname) > 64 {
		return User{}, errors.New("user service: user nick name too long: max allowed 64 characters")
	}
	return user, nil
}

func (us userService) CreateUser(ctx context.Context, user User) {
}
