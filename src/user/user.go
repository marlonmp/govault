package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID
	Nickname  string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}
