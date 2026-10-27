package keyset

import (
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/marlonmp/govault/pkg/crypto"
)

type Keyset struct {
	ID             uuid.UUID
	SequenceNumber int
	EncSymKey      *crypto.JWE      `json:"enc_sym_key"`
	EncPrivKey     *crypto.JWE      `json:"enc_priv_key"`
	PubKey         jwk.RSAPublicKey `json:"pub_key"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
