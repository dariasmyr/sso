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
	sessionSaver    SessionSaver
	sessionProvider SessionProvider
	tokenTTL        time.Duration
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AccountSaver interface {
	SaveAccount(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type AccountProvider interface {
	Account(ctx context.Context, email string) (models.Account, error)
	IsAdmin(ctx context.Context, accountId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int64) (models.App, error)
}

type SessionSaver interface {
	SaveSession(ctx context.Context, accountId int64, token string, expiresAt time.Time) (sessionID string, err error)
}

type SessionProvider interface {
	GetActiveSessions(ctx context.Context, accountId int64) ([]models.Session, error)
	RefreshSession(ctx context.Context, sessionID string, refreshToken string) (newToken string, newRefreshToken string, expiresAt time.Time, err error)
	ValidateSession(ctx context.Context, token string) (valid bool, expiresAt time.Time, err error)
	RevokeSession(ctx context.Context, token string) (success bool, err error)
}

func New(
	log *slog.Logger,
	accountSaver AccountSaver,
	accountProvider AccountProvider,
	appProvider AppProvider,
	sessionSaver SessionSaver,
	sessionProvider SessionProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:             log,
		accountSaver:    accountSaver,
		accountProvider: accountProvider,
		appProvider:     appProvider,
		sessionSaver:    sessionSaver,
		sessionProvider: sessionProvider,
		tokenTTL:        tokenTTL,
	}
}
