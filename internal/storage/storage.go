package storage

import "errors"

var (
	ErrAccountExists   = errors.New("account already exists")
	ErrAccountNotFound = errors.New("account not found")
	ErrAppNotFound     = errors.New("account not found")
	ErrAppExists       = errors.New("app already exists")
	ErrSessionNotFound = errors.New("session not found")
)
