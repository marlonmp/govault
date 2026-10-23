package auth

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/1Password/srp"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/internal/keyset"
	"github.com/marlonmp/govault/pkg/crypto"
	"github.com/marlonmp/govault/pkg/errs"
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

type UserAuthField struct {
	Method     string `json:"method"`
	Alg        string `json:"alg"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Verifier   []byte `json:"v"`
}

func (field *UserAuthField) Validate(vctx vals.ErrorContext) *UserAuthField {
	if field.Alg != "PBES2g-HS256" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "method",
			Message: "algorithm not supported",
		})
	}
	if field.Method != "SRPg-4096" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "method",
			Message: "method not supported",
		})
	}
	if field.Iterations < crypto.PBES2MinIters || field.Iterations > crypto.PBES2MaxIters {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "iterations",
			Message: fmt.Sprintf("iterations must be between %d and %d", crypto.PBES2MinIters, crypto.PBES2MaxIters),
		})
	}
	if len(field.Salt) < int(crypto.EncrytionSaltLen) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "salt",
			Message: fmt.Sprintf("a salt of mininum %d bytes is required", crypto.EncrytionSaltLen),
		})
	}
	v := new(big.Int).SetBytes(field.Verifier)
	group := srp.KnownGroups[srp.RFC5054Group3072]
	server := srp.NewSRPServer(group, v, nil)
	if server == nil {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "v",
			Message: "this is not a valid SRP verifier",
		})
	}
	return field
}

type UserField struct {
	Email     string `json:"email"`
	Nickname  string `json:"nickname"`
	KeyFormat string `json:"key_format"`
	KeyUUID   string `json:"key_uuid"`
}

func (field UserField) Validate(vctx vals.ErrorContext) UserField {
	field.Nickname = vals.ValidateNickname(field.Nickname, vctx.Extend("nickname"))
	field.Email = vals.ValidateEmail(field.Email, vctx.Extend("email"))
	if field.KeyFormat != "A3" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "key_format",
			Message: "invalid secret key format",
		})
	}
	if len(field.KeyUUID) != 6 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "key_uuid",
			Message: "invalid secret key uuid",
		})
	}
	return field
}

type KeysetField struct {
	ID             uuid.UUID        `json:"uuid"`
	SequenceNumber int              `json:"sn"`
	EncryptedBy    string           `json:"encrypted_by"`
	EncSymKey      *keyset.JWE   `json:"enc_sym_key"`
	EncPrivKey     *keyset.JWE   `json:"enc_priv_key"`
	PubKeyImport   json.RawMessage  `json:"pub_key"`
	PubKey         jwk.RSAPublicKey `json:"-"`
}

func (field *KeysetField) Validate(vctx vals.ErrorContext) *KeysetField {
	if field.ID == uuid.Nil {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "uuid",
			Message: "this field is required",
		})
	}
	if field.SequenceNumber < 1 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "sn",
			Message: "this field must be greater than 0",
		})
	}
	if field.EncryptedBy != "mp" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "encrypted_by",
			Message: "value not supported",
		})
	}
	field.EncSymKey.Validate(vctx.Extend("enc_sym_key"))
	field.EncPrivKey.Validate(vctx.Extend("enc_priv_key"))
	pubKey, err := jwk.Import[jwk.RSAPublicKey](field)
	field.PubKey = pubKey
	if err != nil {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "pub_key",
			Message: "invalid public key",
		})
	}
	return field
}

type SignupPayload struct {
	SignupID string        `json:"signup_uuid"`
	User     UserField     `json:"user"`
	Keyset   KeysetField   `json:"keyset"`
	UserAuth UserAuthField `json:"user_auth"`
}

func (payload *SignupPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	payload.User.Validate(vctx)
	payload.Keyset.Validate(vctx)
	payload.UserAuth.Validate(vctx)
	return vctx.GetError("there are errors in the payload", "some field errors were found")
}

type StartPayload struct {
	Email     string `json:"email"`
	KeyFormat string `json:"key_format"`
	KeyUUID   string `json:"key_uuid"`
}

func (payload StartPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	if payload.KeyFormat != "A3" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "key_format",
			Message: "invalid secret key format",
		})
	}
	if len(payload.KeyUUID) != 6 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "key_uuid",
			Message: "invalid secret key uuid",
		})
	}
	return vctx.GetError("there are errors in the payload", "some field errors were found")
}

type AuthPayload struct {
	UserEphemeralPublic string `json:"user_a"`
}

type ConfirmKeyPayload struct {
	ClientProof []byte `json:"user_verification_hash"`
}
