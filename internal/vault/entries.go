package vault

import (
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/pkg/crypto"
)

type ItemFieldType string

const (
	ItemFieldUser   ItemFieldType = "user" // username or emails
	ItemFieldSecret ItemFieldType = "secret"
	ItemFieldTOTP   ItemFieldType = "totp"
	ItemFieldText   ItemFieldType = "text"
	ItemFieldURL    ItemFieldType = "url"
)

// vault items

type ItemField struct {
	ID    uuid.UUID     `json:"id"`
	Name  string        `json:"name"`
	Type  ItemFieldType `json:"type"`
	Value []byte        `json:"value"`
}

func (f *ItemField) Clear() {
	if (f.Type != ItemFieldSecret && f.Type != ItemFieldTOTP) {
		return
	}
	subtle.XORBytes(f.Value, f.Value, f.Value)
}

type Item struct {
	ID        uuid.UUID   `json:"id"`
	Fields    []ItemField `json:"fields"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

func (i *Item) Clear() {
	for _, field := range i.Fields {
		field.Clear()
	}
}

type EncItem struct {
	ID   uuid.UUID   `json:"id"`
	Data *crypto.JWE `json:"data"`
}

func (i *EncItem) Decrypt(symKey []byte) (*Item, error) {
	return i.Decrypt(symKey)
}

type ItemOverview struct {
	ID         uuid.UUID   `json:"id"`
	Title      string      `json:"title"`
	Tags       []string    `json:"tags"`
	Fields     []ItemField `json:"fields"`
	IsArchived bool        `json:"is_archived"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// vaults

type Vault struct {
	ID             uuid.UUID             `json:"id"`
	Name           string                `json:"name"`
	ItemsOverview  []ItemOverview        `json:"items_overview"`
	EncItems       map[uuid.UUID]EncItem `json:"enc_items"`
	SequenceNumber int                   `json:"-"`
	EncSymKey      *crypto.JWE           `json:"-"`
	IsReadOnly     bool                  `json:"-"`
	CreatedAt      time.Time             `json:"-"`
	UpdatedAt      time.Time             `json:"-"`
}

func (v *Vault) Decrypt(itemID uuid.UUID, priv *rsa.PrivateKey) (*Item, error) {
	symKey, err := v.EncSymKey.DecryptRSAPrivKey(priv)
	if err != nil {
		return nil, err
	}
	defer subtle.XORBytes(symKey, symKey, symKey)
	encItem, ok := v.EncItems[itemID]
	if !ok {
		return nil, errors.New("no item found")
	}
	return encItem.Decrypt(symKey)
}

type EncVault struct {
	ID             uuid.UUID
	Name           string
	EncSymKey      *crypto.JWE
	Data           *crypto.JWE
	SequenceNumber int
	IsReadOnly     bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (v *EncVault) Decrypt(priv *rsa.PrivateKey) (*Vault, error) {
	symKey, err := v.EncSymKey.DecryptRSAPrivKey(priv)
	if err != nil {
		return nil, err
	}
	defer subtle.XORBytes(symKey, symKey, symKey)
	data, err := v.Data.DecryptA256GCM(symKey)
	if err != nil {
		return nil, err
	}
	var vault *Vault
	err = json.Unmarshal(data, vault)
	return vault, err
}

// overviews

type OverviewField struct {
	FieldID uuid.UUID
	ItemID  uuid.UUID
	VaultID uuid.UUID
	Type    ItemFieldType
	Name    string
	Value   string
}

type Overview struct {
	// this is used for trigram search
	InvertedMap map[string][]uuid.UUID
	Fields      map[uuid.UUID]OverviewField
}
