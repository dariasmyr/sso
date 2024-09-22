package auth

import (
	"context"
	"errors"
	"log/slog"
	"sso/internal/domain/models"
	"time"
)

type Auth struct {
	log             *slog.Logger
	accountSaver    AccountSaver
	accountProvider AccountProvider
	appProvider     AppProvider
	tokenTTL        time.Duration
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AccountSaver interface {
	SaveAccount(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type AccountProvider interface {
	Account(ctx context.Context, email string) (models.Account, error)
	IsAdmin(ctx context.Context, accountId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int64) (models.App, error)
}

func New(
	log *slog.Logger,
	accountSaver AccountSaver,
	accountProvider AccountProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		accountSaver:    accountSaver,
		accountProvider: accountProvider,
		log:             log,
		appProvider:     appProvider,
		tokenTTL:        tokenTTL,
	}
}
