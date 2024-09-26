package storage

import "errors"

var (
	ErrAccountExists   = errors.New("account already exists")
	ErrAccountNotFound = errors.New("account not found")
	ErrAppNotFound     = errors.New("account not found")
)
