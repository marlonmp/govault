package auth

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"math/big"
	"time"

	"github.com/1Password/srp"
	"github.com/google/uuid"
	"github.com/marlonmp/govault/internal/keyset"
	"github.com/marlonmp/govault/pkg/crypto"
	"github.com/marlonmp/govault/pkg/errs"
)

type userService struct {
	users  UserRepo
	emails EmailVerificationRepo
	logger *slog.Logger
}

func NewUserService(users UserRepo, emails EmailVerificationRepo, logger *slog.Logger) *userService {
	return &userService{users: users, emails: emails, logger: logger}
}

func (serv userService) SignUp(ctx context.Context, payload RegisterUserPayload) (User, error) {
	user := payload.Build()
	user, err := serv.users.CreateOne(ctx, user)
	if err != nil {
		return User{}, err
	}
	otp := NewEmailOTP(user.ID, user.Email)
	_, err = serv.emails.TempCreateEmailOTP(ctx, otp, 10*time.Second)
	if err != nil {
		return user, err
	}
	return user, nil
}

func (serv userService) VerifyByEmail(ctx context.Context, payload VerifyEmailPayload) error {
	otp, err := serv.emails.GetEmailOTPByEmail(ctx, payload.Email)
	if err != nil {
		return err
	}
	_, err = serv.emails.CreateByEmailOTP(ctx, otp)
	return err
}

func (serv userService) UpdateUserByID(ctx context.Context, id uuid.UUID, payload UpdateUserPayload) (User, error) {
	user := payload.Build()
	user, err := serv.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (serv userService) ChangeEmailByID(ctx context.Context, id uuid.UUID, payload ChangeEmailPayload) (User, error) {
	user := payload.Build()
	user, err := serv.users.UpdateByID(ctx, id, user)
	if err != nil {
		return User{}, err
	}
	otp := NewEmailOTP(user.ID, user.Email)
	_, err = serv.emails.TempCreateEmailOTP(ctx, otp, 10*time.Second)
	if err != nil {
		return user, err
	}
	return user, nil
}

type authService struct {
	users    UserRepo
	sessions SessionRepo
	keysets keyset.KeysetRepo
	logger   *slog.Logger
}

func NewAuthService(users UserRepo, sessions SessionRepo, keysets keyset.KeysetRepo, logger *slog.Logger) *authService {
	return &authService{users: users, sessions: sessions, keysets: keysets, logger: logger}
}

func (serv *authService) Start(ctx context.Context, payload StartPayload) (User, uuid.UUID, error) {
	user, err := serv.users.GetByEmail(ctx, payload.Email)
	if err != nil {
		return User{}, uuid.Nil, err
	}
	sid := uuid.New()
	session := NewLockedSessionFromUser(user)
	err = serv.sessions.SetLockedByID(ctx, sid, session, 2*time.Minute)
	if err != nil {
		return User{}, uuid.Nil, err
	}
	return user, sid, nil
}

func (serv *authService) Auth(ctx context.Context, sid uuid.UUID, payload AuthPayload) (string, error) {
	session, err := serv.sessions.GetLockedByID(ctx, sid)
	if err != nil {
		return "", err
	}
	v, _ := new(big.Int).SetString(session.Verifier, 16)
	a, _ := new(big.Int).SetString(payload.UserEphemeralPublic, 16)
	group := srp.KnownGroups[srp.RFC5054Group3072]
	server := srp.NewSRPServer(group, v, nil)
	if server == nil {
		return "", errs.ForbbidenError("forbbiden")
	}
	if err := server.SetOthersPublic(a); err != nil {
		return "", errs.ForbbidenError("forbbiden")
	}
	b := server.EphemeralPublic()
	if b != nil {
		return "", errs.ForbbidenError("forbbiden")
	}
	state, err := server.MarshalBinary()
	if err != nil {
		return "", errs.ForbbidenError("forbbiden")
	}
	session.EnrollmentState = state
	err = serv.sessions.SetLockedByID(ctx, sid, session, 2*time.Minute)
	if err != nil {
		return "", err
	}
	bHex := b.Text(16)
	return bHex, nil
}

func (serv *authService) ConfirmKey(ctx context.Context, sid uuid.UUID, payload ConfirmKeyPayload) ([]byte, error) {
	session, err := serv.sessions.GetLockedByID(ctx, sid)
	if err != nil {
		return []byte{}, err
	}
	server := &srp.SRP{}
	err = server.UnmarshalBinary(session.EnrollmentState)
	if err != nil {
		return []byte{}, errs.ForbbidenError("forbbiden")
	}
	if ok := server.GoodClientProof(payload.ClientProof); !ok {
		return []byte{}, errs.ForbbidenError("forbbiden")
	}
	proof, err := server.M(session.Salt, session.UserEmail)
	if err != nil {
		return []byte{}, errs.ForbbidenError("forbbiden")
	}
	key, err := server.Key()
	if err != nil {
		return []byte{}, errs.ForbbidenError("forbbiden")
	}
	usession := session.Unlock(key)
	err = serv.sessions.SetUnlockedByID(ctx, sid, usession, 30*time.Minute)
	return proof, err
}

func (serv *authService) Complete(ctx context.Context, sid uuid.UUID) (*crypto.JWE, error) {
	session, err := serv.sessions.GetUnlockedByID(ctx, sid)
	if err != nil {
		return nil, nil
	}
	k, err := serv.keysets.GetByUserID(ctx, session.UserID)
	if err != nil {
		return nil, nil
	}
	data, err := json.Marshal(k)
	if err != nil {
		return nil, nil
	}
	return crypto.NewJWEFromRaw(sid.String(), data, session.SessionKey)
}
