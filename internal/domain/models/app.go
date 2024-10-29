package models

import "time"

type App struct {
	ID          int32
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Name        string
	Secret      string
	RedirectUrl string
}
