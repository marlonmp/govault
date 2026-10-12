package crypto

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/1Password/srp"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/marlonmp/govault/pkg/vals"
)

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

type DeviceField struct {
	ID            uuid.UUID `json:"uuid"`
	ClientName    string    `json:"client_name"`
	ClientVersion string    `json:"client_version"`
	UserAgent     string    `json:"user_agent"`
	OsName        string    `json:"os_name"`
}

func (field DeviceField) Validate(vctx vals.ErrorContext) DeviceField {
	if field.ID == uuid.Nil {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "uuid",
			Message: "this field is required",
		})
	}
	return field
}

type KeysetField struct {
	ID             uuid.UUID        `json:"uuid"`
	SequenceNumber int              `json:"sn"`
	EncryptedBy    string           `json:"encrypted_by"`
	EncSymKey      *EncJWK          `json:"enc_sym_key"`
	EncPrivKey     *EncJWK          `json:"enc_priv_key"`
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
	if field.Iterations < PBES2MinIters || field.Iterations > PBES2MaxIters {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "iterations",
			Message: fmt.Sprint("iterations must be between %d and %d", PBES2MinIters, PBES2MaxIters),
		})
	}
	if len(field.Salt) < int(EncrytionSaltLen) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "salt",
			Message: fmt.Sprintf("a salt of mininum %d bytes is required", EncrytionSaltLen),
		})
	}
	v := new(big.Int).SetBytes(field.Verifier)
	group := srp.KnownGroups[srp.RFC5054Group3072]
	server := srp.NewSRPServer(group, v, nil)
	if server == nil {
		vctx.AddErrors(errs.AppErrorItem{
			Code: "invalid_value",
			Path: "v",
			Message: "this is not a valid SRP verifier",
		})
	}
	return field
}

type SignupPayload struct {
	SignupID string        `json:"signup_uuid"`
	User     UserField     `json:"user"`
	Device   DeviceField   `json:"device"`
	Keyset   KeysetField   `json:"keyset"`
	UserAuth UserAuthField `json:"user_auth"`
}

func (payload *SignupPayload) Validate() error {
	vctx := vals.NewErrorContext("")
	payload.User.Validate(vctx)
	payload.Device.Validate(vctx)
	payload.Keyset.Validate(vctx)
	payload.UserAuth.Validate(vctx)
	return vctx.GetError("there are errors in the payload", "some field errors were found")
}
