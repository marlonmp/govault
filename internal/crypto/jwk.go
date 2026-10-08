package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
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
	fmt.Println()
	fmt.Println("encprivkeyi", string(privJson))
	kid, _ := priv.KeyID()
	data, iv, err := EncryptAESGCMV2(privJson, auk)
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
	fmt.Println()
	fmt.Println("encsymkey", string(aukJson))
	kid, _ := auk.KeyID()
	salt := GenerateRandomKey(16)
	iters := 650_000
	info := "encSymKey"
	derivatedKey, err := TwoSecretKeyDerivationV2(password, secretKey, salt, info, iters)
	if err != nil {
		return nil, nil
	}
	data, iv, err := EncryptAESGCMV2(aukJson, derivatedKey)
	if err != nil {
		return nil, nil
	}
	enc := &EncJWK{
		KID:  kid,
		ENC:  "A256GCM",
		CTY:  "b5+jwk+json",
		IV:   iv,
		Data: data,
		ALG: "PBES2g-HS256",
		P2C: iters,
		P2S: salt,
	}
	return enc, nil
}
