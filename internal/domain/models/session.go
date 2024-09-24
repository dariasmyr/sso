package models

import "time"

type Session struct {
	ID               int64
	AccountID        int64
	Token            string
	RefreshToken     string
	UserAgent        string
	IPAddress        string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Revoked          bool
}
