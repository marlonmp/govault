package crypto

import (
	"crypto/x509"
	"fmt"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/pkg/errs"
)

type UserField struct {
	Email            string `json:"email"`
	Name             string `json:"name"`
	AccountKeyFormat string `json:"account_key_format"`
	AccountKeyUUID   string `json:"account_key_uuid"`
}

type DeviceField struct {
	ID            uuid.UUID `json:"uuid"`
	ClientName    string    `json:"client_name"`
	ClientVersion string    `json:"client_version"`
	UserAgent     string    `json:"user_agent"`
	OsName        string    `json:"os_name"`
}

type KeysetField struct {
	ID             uuid.UUID        `json:"uuid"`
	SequenceNumber int              `json:"sn"`
	EncryptedBy    string           `json:"encrypted_by"`
	EncSymKey      *EncJWK          `json:"enc_sym_key"`
	EncPrivKey     *EncJWK          `json:"enc_priv_key"`
	PubKey         jwk.RSAPublicKey `json:"pub_key"`
}

type UserAuthField struct {
	Method     string `json:"method"`
	Alg        string `json:"alg"`
	Iterations string `json:"iterations"`
	Salt       string `json:"salt"`
	Verifier   []byte `json:"v"`
}

type SignupPayload struct {
	SignupID string        `json:"signup_uuid"`
	User     UserField     `json:"user"`
	Device   DeviceField   `json:"device"`
	Keyset   KeysetField   `json:"keyset"`
	UserAuth UserAuthField `json:"user_auth"`
}

type CreateEncKeysetPayload struct {
	EncSalt    []byte `json:"enc_salt"`
	AuthSalt   []byte `json:"auth_salt"`
	EncSymKey  []byte `json:"enc_sym_key"`
	EncPrivKey []byte `json:"enc_priv_key"`
	PubKey     []byte `json:"pub_key"`
}

func (payload *CreateEncKeysetPayload) test() {
	jwk.Parse(nil, nil)
}

func (payload *CreateEncKeysetPayload) GetValidationErrors() error {
	errors := make([]errs.AppErrorItem, 0)
	if len(payload.EncSalt) != int(EncrytionSaltLen) {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/enc_salt",
			Message: fmt.Sprintf("a %d long salt was excected", len(payload.EncSalt)),
		}
		errors = append(errors, err)
	}
	if len(payload.AuthSalt) != int(AuthenticationSaltLen) {
		err := errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "/auth_salt",
			Message: fmt.Sprintf("a %d long salt was excected", len(payload.AuthSalt)),
		}
		errors = append(errors, err)
	}
	if _, err := x509.ParsePKCS1PublicKey(payload.PubKey); err != nil {
		err := errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "/pub_key",
			Message: "this is not a valid public key",
		}
		errors = append(errors, err)
	}
	// TODO: implement better enc priv key validation
	if len(payload.EncPrivKey) < (PrivateKeyBits >> 3) {
		err := errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "/enc_priv_key",
			Message: "it seems to be a non valid encrypted private key",
		}
		errors = append(errors, err)
	}
	// TODO: implement better enc sym key validation
	if len(payload.EncSymKey) < 32 {
		err := errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "/enc_sym_key",
			Message: "it seems to be a non valid encrypted symetric key",
		}
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errs.ValidationError("invalid keyset", "there was an error validating the keyset fields", errors...)
	}
	return nil
}
