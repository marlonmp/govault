package user

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type SecretKeyMetadata struct {
	KeyID     string
	KeyFormat string
}

func (skm *SecretKeyMetadata) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("expected jsonb")
	}
	return json.Unmarshal(bytes, skm)
}

func (skm SecretKeyMetadata) Value() (driver.Value, error) {
	return json.Marshal(skm)
}

type UserAuth struct {
	Method     string
	Alg        string
	Iterations int
	Salt       []byte
	Verifier   []byte
}

func (au *UserAuth) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("expected jsonb")
	}
	return json.Unmarshal(bytes, au)
}

func (au *UserAuth) Value() (driver.Value, error) {
	return json.Marshal(au)
}

type User struct {
	ID        uuid.UUID
	Nickname  string
	Email     string
	Auth      UserAuth
	SecretKey SecretKeyMetadata
	CreatedAt time.Time
	UpdatedAt time.Time
}

type EmailVerification struct {
	ID        uuid.UUID
	OTP       string
	CreatedAt time.Time
	ExpiresAt time.Time
	AppliedAt *time.Time
}

type DeviceMetadata struct {
	ID            uuid.UUID
	ClientName    string
	ClientVersion string
	UserAgent     string
	OsName        string
}

func (dm *DeviceMetadata) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("expected jsonb")
	}
	return json.Unmarshal(bytes, dm)
}

func (dm DeviceMetadata) Value() (driver.Value, error) {
	return json.Marshal(dm)
}

type Device struct {
	ID        uuid.UUID
	Data      DeviceMetadata
	CreatedAt time.Time
	UpdatedAt time.Time
}
