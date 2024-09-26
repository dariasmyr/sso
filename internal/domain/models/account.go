package models

import "time"

type Account struct {
	ID        int64
	CreatedAt time.Time
	UpdatedAt time.Time
	Email     string
	PassHash  []byte
	Roles     []AccountRole
	Status    AccountStatus
	AppId     int64
}

type AccountRole int32

const (
	USER  AccountRole = 0
	ADMIN AccountRole = 1
)

type AccountStatus int32

const (
	ACTIVE   AccountStatus = 0
	INACTIVE AccountStatus = 1
	DELETED  AccountStatus = 2
)
