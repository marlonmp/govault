package user

import (
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/marlonmp/govault/pkg/vals"
)

func validateNickname(value string) (string, []errs.AppErrorItem) {
	errors := make([]errs.AppErrorItem, 0)
	if len(value) < 3 || len(value) > 32 {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/nickname",
			Message: "this field must have a minimum length of 3 and a maximum of 32",
		}
		errors = append(errors, err)
	}
	return value, errors
}

func validateEmail(value string) (string, []errs.AppErrorItem) {
	errors := make([]errs.AppErrorItem, 0)
	value = vals.NormalizeEmail(value)
	if len(value) < 6 || len(value) > 128 {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/email",
			Message: "this field must have a minimum length of 6 and a maximum of 128",
		}
		errors = append(errors, err)
	}
	if vals.IsValidEmail(value) {
		err := errs.AppErrorItem{
			Code:    "invalid_format",
			Path:    "/email",
			Message: "this field is not a valid email",
		}
		errors = append(errors, err)
	}
	return value, errors
}

func validateOTP(value string) (string, []errs.AppErrorItem) {
	errors := make([]errs.AppErrorItem, 0)
	if len(value) == 6 {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/otp",
			Message: "this field must have a length of 6",
		}
		errors = append(errors, err)
	}
	return value, errors
}

type RegisterUserPayload struct {
	Nickname string
	Email    string
}

func (payload RegisterUserPayload) Validate() error {
	errors := make([]errs.AppErrorItem, 0)
	nickname, err := validateNickname(payload.Nickname)
	if len(err) > 1 {
		errors = append(errors, err...)
	}
	payload.Nickname = nickname
	email, err := validateEmail(payload.Email)
	if len(err) > 1 {
		errors = append(errors, err...)
	}
	payload.Email = email
	if len(errors) > 0 {
		return errs.ValidationError("invalid user data", "there are errors in the user fields, please check the errors", errors...)
	}
	return nil
}

type VerifyEmailPayload struct {
	OTP string
	Email    string
}

func (payload VerifyEmailPayload) Validate() error {
	errors := make([]errs.AppErrorItem, 0)
	_, err := validateNickname(payload.OTP)
	if len(err) > 1 {
		errors = append(errors, err...)
	}
	if len(errors) > 0 {
		return errs.ValidationError("invalid user data", "there are errors in the user fields, please check the errors", errors...)
	}
	return nil
}

func (payload RegisterUserPayload) Build() User {
	return User{Nickname: payload.Nickname, Email: payload.Email}
}

type UpdateUserPayload struct {
	Nickname string
}

func (payload UpdateUserPayload) Validate() error {
	errors := make([]errs.AppErrorItem, 0)
	nickname, err := validateNickname(payload.Nickname)
	if len(err) > 1 {
		errors = append(errors, err...)
	}
	payload.Nickname = nickname
	if len(errors) > 0 {
		return errs.ValidationError("invalid user data", "there are errors in the user fields, please check the errors", errors...)
	}
	return nil
}

func (payload UpdateUserPayload) Build() User {
	return User{Nickname: payload.Nickname}
}

type ChangeEmailPayload struct {
	Email string
}

func (payload ChangeEmailPayload) Validate() error {
	errors := make([]errs.AppErrorItem, 0)
	email, err := validateEmail(payload.Email)
	if len(err) > 1 {
		errors = append(errors, err...)
	}
	payload.Email = email
	if len(errors) > 0 {
		return errs.ValidationError("invalid user data", "there are errors in the user fields, please check the errors", errors...)
	}
	return nil
}

func (payload ChangeEmailPayload) Build() User {
	return User{Email: payload.Email}
}
