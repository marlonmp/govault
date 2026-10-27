package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/pkg/errs"
	"github.com/marlonmp/govault/pkg/vals"
)

type JWE struct {
	KID  string `json:"kid"`
	ENC  string `json:"enc"`
	CTY  string `json:"cty"`
	IV   []byte `json:"iv"`
	Data []byte `json:"data"`
	ALG  string `json:"alg,omitempty"`
	P2C  int    `json:"p2c,omitempty"`
	P2S  []byte `json:"p2s,omitempty"`
}

func NewJWEFromRaw(kid string, raw, key []byte) (*JWE, error){
	jwe := &JWE{KID: kid, ENC: "A256GCM", CTY: "b5+jwk+json"}
	iv, data, err := EncryptA256GCM(raw, key)
	jwe.Data = data
	jwe.IV = iv
	return jwe, err
}

func ImportEncPrivKey(priv jwk.RSAPrivateKey, auk []byte) (*JWE, error) {
	privJson, err := json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	kid, _ := priv.KeyID()
	iv, data, err := EncryptA256GCM(privJson, auk)
	if err != nil {
		return nil, err
	}
	enc := &JWE{
		KID:  kid,
		ENC:  "A256GCM",
		CTY:  "b5+jwk+json",
		IV:   iv,
		Data: data,
	}
	return enc, nil
}

func ImportEncSymKey(auk jwk.SymmetricKey, password, secretKey []byte) (*JWE, error) {
	aukJson, err := json.Marshal(auk)
	if err != nil {
		return nil, err
	}
	kid, _ := auk.KeyID()
	salt := GenerateRandomKey(16)
	iters := 650_000
	info := "encSymKey"
	derivatedKey, err := PBES2_HS256(password, secretKey, salt, info, iters)
	if err != nil {
		return nil, nil
	}
	iv, data, err := EncryptA256GCM(aukJson, derivatedKey)
	if err != nil {
		return nil, nil
	}
	enc := &JWE{
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

func (jwe *JWE) Validate(vctx vals.ErrorContext) *JWE {
	if len(jwe.KID) < 2 {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "kid",
			Message: "a value at least of 2 characters was excpected",
		})
	}
	if jwe.ENC != "A256GCM" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "enc",
			Message: "encryption type not supported",
		})
	}
	if jwe.CTY != "b5+jwk+json" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "cty",
			Message: "content type not supported",
		})
	}
	if len(jwe.IV) < int(EncrytionSaltLen) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "iv",
			Message: fmt.Sprintf("a salt of mininum %d bytes is required", EncrytionSaltLen),
		})
	}
	if jwe.ALG != "" && jwe.ALG != "PBES2g-HS256" {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "alg",
			Message: "algorithm not supported",
		})
	}
	if jwe.P2C < PBES2MinIters || jwe.P2C > PBES2MaxIters {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_value",
			Path:    "p2c",
			Message: fmt.Sprintf("iterations must be between %d and %d", PBES2MinIters, PBES2MaxIters),
		})
	}
	if len(jwe.P2S) < int(EncrytionSaltLen) {
		vctx.AddErrors(errs.AppErrorItem{
			Code:    "invalid_length",
			Path:    "p2s",
			Message: fmt.Sprintf("a salt of mininum %d bytes is required", EncrytionSaltLen),
		})
	}
	return jwe
}

func (jwe *JWE) Decrypt(key []byte) ([]byte, error) {
	return DecryptA256GCM(jwe.IV, jwe.Data, key)
}
