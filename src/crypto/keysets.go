package crypto

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/google/uuid"
)

type EncKeyset struct {
	ID                 uuid.UUID
	EncryptoinSalt     []byte
	AuthenticationSalt []byte
	SRPVerifier        []byte
	Pub                []byte
	EncPriv            []byte
}

func (ek *EncKeyset) Unlock(derivatedKey []byte) (*Keyset, error) {
	privBytes, err := EncryptAESGCM(ek.EncPriv, derivatedKey)
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	keyset := &Keyset{
		ID:                 ek.ID,
		EncryptoinSalt:     ek.EncryptoinSalt,
		AuthenticationSalt: ek.AuthenticationSalt,
		SRPVerifier:        ek.SRPVerifier,
		Priv:               priv,
	}
	return keyset, nil
}

type Keyset struct {
	ID                 uuid.UUID
	EncryptoinSalt     []byte
	AuthenticationSalt []byte
	SRPVerifier        []byte
	Priv               *rsa.PrivateKey
}

// TODO: implement private key erasing from mmemory
func (k *Keyset) erase() {
}

func (k *Keyset) Lock(derivatedKey []byte) (*EncKeyset, error) {
	privBytes := x509.MarshalPKCS1PrivateKey(k.Priv)
	encPriv, err := EncryptAESGCM(privBytes, derivatedKey)
	if err != nil {
		return nil, err
	}
	pubBytes := x509.MarshalPKCS1PublicKey(&k.Priv.PublicKey)
	encKeyset := &EncKeyset{
		ID:                 k.ID,
		EncryptoinSalt:     k.EncryptoinSalt,
		AuthenticationSalt: k.AuthenticationSalt,
		SRPVerifier:        k.SRPVerifier,
		Pub:                pubBytes,
		EncPriv:            encPriv,
	}
	k.erase()
	return encKeyset, nil
}
