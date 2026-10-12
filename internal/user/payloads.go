package user

import (
	"github.com/marlonmp/govault/pkg/vals"
)

type RegisterUserPayload struct {
	Nickname string
	Email    string
}

func (payload RegisterUserPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	payload.Nickname = vals.ValidateNickname(payload.Nickname, vctx.Extend("nickname"))
	payload.Email = vals.ValidateEmail(payload.Email, vctx.Extend("email"))
	return vctx.GetError("invalid user data", "there are errors in the user fields")
}

type VerifyEmailPayload struct {
	OTP   string
	Email string
}

func (payload VerifyEmailPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	payload.OTP = vals.ValidateNickname(payload.OTP, vctx.Extend("otp"))
	return vctx.GetError("invalid user data", "there are errors in the user fields, please check the errors")
}

func (payload RegisterUserPayload) Build() User {
	return User{Nickname: payload.Nickname, Email: payload.Email}
}

type UpdateUserPayload struct {
	Nickname string
}

func (payload UpdateUserPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	payload.Nickname = vals.ValidateNickname(payload.Nickname, vctx.Extend("nickname"))
	return vctx.GetError("invalid user data", "there are errors in the user fields")
}

func (payload UpdateUserPayload) Build() User {
	return User{Nickname: payload.Nickname}
}

type ChangeEmailPayload struct {
	Email string
}

func (payload ChangeEmailPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	payload.Email = vals.ValidateEmail(payload.Email, vctx.Extend("email"))
	return vctx.GetError("invalid user data", "there are errors in the user fields")
}

func (payload ChangeEmailPayload) Build() User {
	return User{Email: payload.Email}
}
