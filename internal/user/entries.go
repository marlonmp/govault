package user

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	OTPLen = 6
	OTPCharset = "0123456789"

)

// TODO: move this util to pkg
func GenerateOTP() string {
	var sb strings.Builder
	charsetOptions := big.NewInt(int64(len(OTPCharset)))
	for i := 0; i < OTPLen; i++ {
		idx, _ := rand.Int(rand.Reader, charsetOptions)
		sb.WriteByte(OTPCharset[idx.Int64()])
	}
	return sb.String()
}

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

type EmailOTP struct {
	UserID    uuid.UUID `json:"user_id"`
	OTP       string    `json:"otp"`
	Email     string    `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

func NewEmailOTP(userID uuid.UUID, email string) EmailOTP {
	otp := GenerateOTP()
	return EmailOTP{UserID: userID, OTP: otp, Email: email}
}

func (e *EmailOTP) SetExpiresAt(duration time.Duration) {
	e.ExpiresAt = time.Now().Add(duration)
}

type EmailVerification struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     string
	CreatedAt time.Time
}

func NewEmailVerificationFromOTP(otp EmailOTP) EmailVerification {
	return EmailVerification{UserID: otp.UserID, Email: otp.Email}
}
