package models

import (
	"time"
)

type Account struct {
	ID        int64
	CreatedAt time.Time
	UpdatedAt time.Time
	Email     string
	PassHash  []byte
	Role      string
	Status    string
	AppId     int32
}
