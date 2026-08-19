package user_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/marlonmp/govault/src/user"
)

func TestPGUserRepo(t *testing.T) {
	// load env
	err := godotenv.Load("../../.env")
	if err != nil {
		t.Fatalf("users repo: cannot setup env: %v", err)
	}
	strConn := os.Getenv("GOOSE_DBSTRING")
	db, err := sql.Open("pgx", strConn)
	if err != nil {
		t.Fatalf("users repo: db set up: cannot connect to db: %v", err)
	}
	repo := user.NewPGUserRepo(db, nil)

	t.Run("create users", func(t *testing.T) {
		ctx := context.Background()
		testcases := []struct {
			user        user.User
			expectedErr error
		}{
			{
				user: user.User{
					Nickname: "nick",
					Email:    "nick@email.com",
				},
				expectedErr: nil,
			},
			{
				user: user.User{
					Nickname: "nick2",
					Email:    "nick@email.com",
				},
				expectedErr: user.UserEmailAlreadyUsedErr,
			},
			{
				user: user.User{
					Nickname: "nick2",
					Email:    "nick2@email.com",
				},
				expectedErr: nil,
			},
		}
		for _, tc := range testcases {
			u, err := repo.CreateOne(ctx, tc.user)
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("users repo: unexpected error on create one user: %v", err)
				continue
			}
			if err != nil {
				continue
			}
			if u.ID == uuid.Nil {
				t.Error("users repo: user created with no id")
			}
			if u.Nickname != tc.user.Nickname {
				t.Errorf("users repo: nicknames are different: %s != %s", u.Nickname, tc.user.Nickname)
			}
			if u.Email != tc.user.Email {
				t.Errorf("users repo: emails are different: %s != %s", u.Email, tc.user.Email)
			}
			if u.CreatedAt.IsZero() {
				t.Error("users repo: created at is not set")
			}
			if u.UpdatedAt.IsZero() {
				t.Error("users repo: updated at is not set")
			}
		}
	})

	t.Run("get user by id", func(t *testing.T) {
		testcases := []struct{
			user user.User
			expectedErr error
		}{
			user: user.User{
				ID: uuid.New(),
				Nickname: "nick junior",
				Email: "nick.jr@email.com",
			}
		}
	})
}
