package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
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
	App(ctx context.Context, appId int) (models.App, error)
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

// Login checks if user with given credentials exists in the system and returns access token.
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	user, err := a.accountProvider.Account(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}
