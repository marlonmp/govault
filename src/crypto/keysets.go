package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/google/uuid"
)

type EncKeyset struct {
	ID          uuid.UUID
	EncSalt     []byte
	AuthSalt    []byte
	SRPVerifier []byte
	PubKey      []byte
	EncPrivKey  []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (ek *EncKeyset) Unlock(derivatedKey []byte) (*Keyset, error) {
	privBytes, err := EncryptAESGCM(ek.EncPrivKey, derivatedKey)
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	keyset := &Keyset{
		ID:                 ek.ID,
		EncryptoinSalt:     ek.EncSalt,
		AuthenticationSalt: ek.AuthSalt,
		SRPVerifier:        ek.SRPVerifier,
		Priv:               priv,
		CreatedAt:          ek.CreatedAt,
		UpdatedAt:          ek.UpdatedAt,
	}
	return keyset, nil
}

type Keyset struct {
	ID                 uuid.UUID
	EncryptoinSalt     []byte
	AuthenticationSalt []byte
	SRPVerifier        []byte
	Priv               *rsa.PrivateKey
	CreatedAt          time.Time
	UpdatedAt          time.Time
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
		ID:          k.ID,
		EncSalt:     k.EncryptoinSalt,
		AuthSalt:    k.AuthenticationSalt,
		SRPVerifier: k.SRPVerifier,
		PubKey:      pubBytes,
		EncPrivKey:  encPriv,
		CreatedAt:   k.CreatedAt,
		UpdatedAt:   k.UpdatedAt,
	}
	k.erase()
	return encKeyset, nil
}
