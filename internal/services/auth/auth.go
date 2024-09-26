package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"time"

	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log             *slog.Logger
	accountSaver    AccountSaver
	accountProvider AccountProvider
	appProvider     AppProvider
	sessionSaver    SessionSaver
	sessionProvider SessionProvider
	tokenTTL        time.Duration
	refreshTokenTTL time.Duration
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
	SaveSession(ctx context.Context, accountId int64, userAgent string, ipAddress string, expiresAt time.Time) (sessionID string, err error)
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
	refreshTokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:             log,
		accountSaver:    accountSaver,
		accountProvider: accountProvider,
		appProvider:     appProvider,
		sessionSaver:    sessionSaver,
		sessionProvider: sessionProvider,
		tokenTTL:        tokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// RegisterNewAccount registers a new account in the system, creates a session, and returns account ID.
func (a *Auth) RegisterNewAccount(ctx context.Context, email string, pass string, userAgent string, ipAddress string) (int64, error) {
	const op = "Auth.RegisterNewAccount"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering account")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.accountSaver.SaveAccount(ctx, email, passHash)
	if err != nil {
		log.Error("failed to save account", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// Login checks if account with given credentials exists in the system and returns access + refresh token.
//
// If account exists, but password is incorrect, returns error.
// If account doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	userAgent string,
	ipAddress string,
	appID int,
) (string, string, error) {
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
			return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		log.Error("failed to generate refresh token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	expiresAt := time.Now().Add(a.refreshTokenTTL)

	sessionID, err := a.sessionSaver.SaveSession(ctx, user.ID, userAgent, ipAddress, expiresAt)
	if err != nil {
		a.log.Error("failed to save session", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("session created", slog.String("session_id", sessionID))

	return token, refreshToken, nil
}

func generateRefreshToken() (string, error) {
	const tokenSize = 32
	token := make([]byte, tokenSize)

	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(token), nil
}
