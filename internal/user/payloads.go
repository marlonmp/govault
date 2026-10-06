package user

import (
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/marlonmp/govault/pkg/vals"
)

type RegisterUserPayload struct {
	Nickname string
	Email    string
}

func (payload RegisterUserPayload) GetValidationError() error {
	errors := make([]errs.AppErrorItem, 0)
	if len(payload.Nickname) < 3 || len(payload.Nickname) > 32 {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/nickname",
			Message: "this field must have a minimum length of 3 and a maximum of 32",
		}
		errors = append(errors, err)
	}
	email := vals.NormalizeEmail(payload.Email)
	if len(email) < 6 || len(email) > 128 {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/email",
			Message: "this field must have a minimum length of 6 and a maximum of 128",
		}
		errors = append(errors, err)
	}
	if vals.IsValidEmail(email) {
		err := errs.AppErrorItem{
			Code:    "invalid_format",
			Path:    "/email",
			Message: "this field is not a valid email",
		}
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errs.ValidationError("invalid user values", "there are errors in the user fields, please check the errors", errors...)
	}
	return nil
}

func (payload RegisterUserPayload) BuildUser() User {
	return User{Nickname: payload.Nickname, Email: payload.Email}
}
