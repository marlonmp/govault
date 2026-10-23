package auth

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/marlonmp/govault/pkg/crypto"
)

const (
	OTPLen     = 6
	OTPCharset = "0123456789"
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
	Verifier   string
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
	otp := crypto.GenerateOTP()
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

type LockedSession struct {
	UserID          uuid.UUID `json:"user_id"`
	UserEmail       string    `json:"user_email"`
	Verifier        string    `json:"v"`
	Salt            []byte    `json:"iv"`
	EnrollmentState []byte    `json:"enrollment_state"`
}

func NewLockedSessionFromUser(user User) *LockedSession {
	return &LockedSession{UserID: user.ID, UserEmail: user.Email, Verifier: user.Auth.Verifier, Salt: user.Auth.Salt}
}

func (ls *LockedSession) Unlock(key []byte) *UnlockedSession {
	return &UnlockedSession{UserID: ls.UserID, UserEmail: ls.UserEmail, SessionKey: key}
}

type UnlockedSession struct {
	UserID     uuid.UUID `json:"user_id"`
	UserEmail  string    `json:"user_email"`
	SessionKey []byte    `json:"key"`
}
