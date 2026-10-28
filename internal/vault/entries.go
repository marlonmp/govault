package vault

import (
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
	Value string        `json:"value"`
}

type Item struct {
	ID        uuid.UUID   `json:"id"`
	Fields    []ItemField `json:"fields"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

type EncItem struct {
	ID   uuid.UUID   `json:"id"`
	Data *crypto.JWE `json:"data"`
}

type ItemOverview struct {
	ID         uuid.UUID
	Title      string
	Tags       []string
	Fields     []ItemField
	IsArchived bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// vaults

type Vault struct {
	ID            uuid.UUID
	Name          string
	ItemsOverview []ItemOverview
	EncItems      map[uuid.UUID]EncItem
	EncSymKey     *crypto.JWE
	IsReadOnly    bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
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
