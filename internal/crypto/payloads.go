package crypto

import (
	"crypto/x509"
	"fmt"

	"github.com/marlonmp/govault/pkg/errs"
)

type CreateEncKeysetPayload struct {
	EncSalt    []byte `json:"enc_salt"`
	AuthSalt   []byte `json:"auth_salt"`
	EncSymKey  []byte `json:"enc_sym_key"`
	EncPrivKey []byte `json:"enc_priv_key"`
	PubKey     []byte `json:"pub_key"`
}

func (payload *CreateEncKeysetPayload) GetValidationErrors() error {
	errors := make([]errs.AppErrorItem, 0)
	if len(payload.EncSalt) != int(EncrytionSaltLen) {
		err := errs.AppErrorItem{
			Code: "invalid_length",
			Path: "/enc_salt",
			Message: fmt.Sprintf("a %d long salt was excected"),
		}
		errors = append(errors, err)
	}
	if len(payload.AuthSalt) != int(AuthenticationSaltLen) {
		err := errs.AppErrorItem{
			Code: "invalid_length",
			Path: "/auth_salt",
			Message: fmt.Sprintf("a %d long salt was excected"),
		}
		errors = append(errors, err)
	}
	if _, err := x509.ParsePKCS1PublicKey(payload.PubKey); err != nil {
		err := errs.AppErrorItem{
			Code: "invalid_value",
			Path: "/pub_key",
			Message: "this is not a valid public key",
		}
		errors = append(errors, err)
	}
	if len(payload.EncPrivKey) < (PrivateKeyBits >> 3) {
		err := errs.AppErrorItem{
			Code: "invalid_value",
			Path: "/enc_priv_key",
			Message: "it seems to be a non valid encrypted private key",
		}
		errors = append(errors, err)
	}
	if len(payload.EncSymKey) < 32 {
		err := errs.AppErrorItem{
			Code: "invalid_value",
			Path: "/enc_sym_key",
			Message: "it seems to be a non valid encrypted symetric key",
		}
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errs.ValidationError("invalid keyset", "there was an error validating the keyset fields", errors...)
	}
	return nil
}
