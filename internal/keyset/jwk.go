package keyset

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/pkg/crypto"
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/marlonmp/govault/pkg/vals"
)

type EncJWK struct {
	KID  string `json:"kid"`
	ENC  string `json:"enc"`
	CTY  string `json:"cty"`
	IV   []byte `json:"iv"`
	Data []byte `json:"data"`
	ALG  string `json:"alg,omitempty"`
	P2C  int    `json:"p2c,omitempty"`
	P2S  []byte `json:"p2s,omitempty"`
}

func ImportEncPrivKey(priv jwk.RSAPrivateKey, auk []byte) (*EncJWK, error) {
	privJson, err := json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	kid, _ := priv.KeyID()
	data, iv, err := crypto.EncryptA256GCM(privJson, auk)
	if err != nil {
		return nil, err
	}
	enc := &EncJWK{
		KID:  kid,
		ENC:  "A256GCM",
		CTY:  "b5+jwk+json",
		IV:   iv,
		Data: data,
	}
	return enc, nil
}

func ImportEncSymKey(auk jwk.SymmetricKey, password, secretKey []byte) (*EncJWK, error) {
	aukJson, err := json.Marshal(auk)
	if err != nil {
		return nil, err
	}
	kid, _ := auk.KeyID()
	salt := crypto.GenerateRandomKey(16)
	iters := 650_000
	info := "encSymKey"
	derivatedKey, err := crypto.PBES2_HS256(password, secretKey, salt, info, iters)
	if err != nil {
		return nil, nil
	}
	data, iv, err := crypto.EncryptA256GCM(aukJson, derivatedKey)
	if err != nil {
		return nil, nil
	}
	enc := &EncJWK{
		KID:  kid,
		ENC:  "A256GCM",
		CTY:  "b5+jwk+json",
		IV:   iv,
		Data: data,
		ALG:  "PBES2g-HS256",
		P2C:  iters,
		P2S:  salt,
	}
	return enc, nil
}

func (ej *EncJWK) Validate(vctx vals.ErrorContext) *EncJWK {
	if len(ej.KID) < 2 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "kid",
			Message: "a value at least of 2 characters was excpected",
		})
	}
	if ej.ENC != "A256GCM" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "enc",
			Message: "encryption type not supported",
		})
	}
	if ej.CTY != "b5+jwk+json" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "cty",
			Message: "content type not supported",
		})
	}
	if len(ej.IV) < int(crypto.EncrytionSaltLen) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "iv",
			Message: fmt.Sprintf("a salt of mininum %d bytes is required", crypto.EncrytionSaltLen),
		})
	}
	if ej.ALG != "" && ej.ALG != "PBES2g-HS256" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "alg",
			Message: "algorithm not supported",
		})
	}
	if ej.P2C < crypto.PBES2MinIters || ej.P2C > crypto.PBES2MaxIters {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "p2c",
			Message: fmt.Sprint("iterations must be between %d and %d", crypto.PBES2MinIters, crypto.PBES2MaxIters),
		})
	}
	if len(ej.P2S) < int(crypto.EncrytionSaltLen) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "p2s",
			Message: fmt.Sprintf("a salt of mininum %d bytes is required", crypto.EncrytionSaltLen),
		})
	}
	return ej
}
