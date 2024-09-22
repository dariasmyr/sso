package models

import "time"

type App struct {
	ID        int64
	CreatedAt time.Time
	UpdatedAt time.Time
	Name      string
	Secret    string
}
