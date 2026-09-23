package user

import (
	"github.com/marlonmp/govault/internal/errs"
	"github.com/marlonmp/govault/pkg/vals"
)

type RegisterUserPayload struct {
	Nickname string
	Email    string
}

func (rup RegisterUserPayload) GetValidationError() error {
	errors := make([]errs.ServiceErrorItem, 0)
	if len(rup.Nickname) < 3 || len(rup.Nickname) > 32 {
		err := errs.ServiceErrorItem{
			Code: "invalid_length",
			Path: "/nickname",
			Message: "this field must have a minimum length of 3 and a maximum of 32",
		}
		errors = append(errors, err)
	}
	email := vals.NormalizeEmail(rup.Email)
	if len(email) < 6 || len(email) > 128 {
		err := errs.ServiceErrorItem{
			Code: "invalid_length",
			Path: "/email",
			Message: "this field must have a minimum length of 6 and a maximum of 128",
		}
		errors = append(errors, err)
	}
	if vals.IsValidEmail(email) {
		err := errs.ServiceErrorItem{
			Code: "invalid_format",
			Path: "/email",
			Message: "this field is not a valid email",
		}
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errs.ValidationError("Invalid user values", "There are errors in the user fields, please check the errors", errors)
	}
	return nil
}

func (rup RegisterUserPayload) GetUser() User {
	return User{Nickname: rup.Nickname, Email: rup.Email}
}
