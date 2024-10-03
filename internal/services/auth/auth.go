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
	"sso/internal/storage"
	"time"

	"crypto/rand"

	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log             *slog.Logger
	accountSaver    AccountSaver
	accountProvider AccountProvider
	appProvider     AppProvider
	appSaver        AppSaver
	sessionSaver    SessionSaver
	sessionProvider SessionProvider
	tokenTTL        time.Duration
	refreshTokenTTL time.Duration
}

// RegisterClient registers a new app in the system, creates an app, and returns app ID.
func (a *Auth) RegisterClient(ctx context.Context, request *ssov1.RegisterClientRequest) (*ssov1.RegisterClientResponse, error) {
	const op = "Auth.RegisterNewApp"

	log := a.log.With(
		slog.String("op", op),
		slog.String("appName", request.GetAppName()),
	)

	log.Info("registering app")

	id, err := a.appSaver.SaveApp(ctx, request.GetAppName(), request.GetSecret(), request.GetRedirectUrl())
	if err != nil {
		log.Error("failed to save app", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &ssov1.RegisterClientResponse{
		AppId: id,
	}, nil
}

// Register registers a new account in the system, creates a session, and returns account ID.
func (a *Auth) Register(ctx context.Context, request *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	const op = "Auth.RegisterNewAccount"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", request.GetEmail()),
	)

	log.Info("registering account")

	passHash, err := bcrypt.GenerateFromPassword([]byte(request.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	status := models.ACTIVE

	modelRole := models.AccountRole(request.GetRole())

	id, err := a.accountSaver.SaveAccount(ctx, request.GetEmail(), passHash, modelRole, status, request.GetAppId())

	if err != nil {
		log.Error("failed to save account", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &ssov1.RegisterResponse{
		AccountId: id,
	}, nil
}

// Login checks if account with given credentials exists in the system and returns access + refresh token.
//
// If account exists, but password is incorrect, returns error.
// If account doesn't exist, returns error.
func (a *Auth) Login(ctx context.Context, request *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", request.GetEmail()),
	)

	log.Info("attempting to login user")

	account, err := a.accountProvider.AccountByEmail(ctx, request.GetEmail())
	if err != nil {
		if errors.Is(err, storage.ErrAccountNotFound) {
			a.log.Warn("account not found", sl.Err(err))
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get account", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(account.PassHash, []byte(request.GetPassword())); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, request.GetAppId())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(account, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		log.Error("failed to generate refresh token", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	expiresAt := time.Now().Add(a.refreshTokenTTL)

	sessionID, err := a.sessionSaver.SaveSession(ctx, account.ID, request.GetUserAgent(), request.GetIpAddress(), token, refreshToken, expiresAt)
	if err != nil {
		a.log.Error("failed to save session", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("session created", slog.String("session_id", sessionID))

	return &ssov1.LoginResponse{
		AccountId:    account.ID,
		Token:        token,
		RefreshToken: refreshToken,
	}, nil
}

// Logout logs out a user by terminating their sessions.
func (a *Auth) Logout(ctx context.Context, request *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	const op = "Auth.Logout"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", request.GetAccountId()),
	)

	log.Info("logging out user")

	// Revoke all sessions for the given account ID.
	sessions, err := a.sessionProvider.Sessions(ctx, request.GetAccountId())
	if err != nil {
		log.Error("failed to get sessions", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	for _, session := range sessions {
		err := a.sessionSaver.RevokeSession(ctx, session.Token)
		if err != nil {
			log.Error("failed to revoke session", sl.Err(err))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	log.Info("user logged out successfully")
	return &ssov1.LogoutResponse{Success: true}, nil
}

func (a *Auth) ChangePassword(ctx context.Context, request *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	const op = "Auth.ChangePassword"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", request.GetAccountId()),
	)

	log.Info("attempting to change password")

	account, err := a.accountProvider.AccountById(ctx, request.GetAccountId())
	if err != nil {
		log.Error("failed to get account", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(account.PassHash, []byte(request.GetOldPassword())); err != nil {
		log.Info("invalid old password", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	newPassHash, err := bcrypt.GenerateFromPassword([]byte(request.GetNewPassword()), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash new password", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	err = a.accountSaver.UpdatePassword(ctx, request.GetAccountId(), newPassHash)
	if err != nil {
		log.Error("failed to update password", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("password changed successfully")
	return &ssov1.ChangePasswordResponse{Success: true}, nil
}

// ChangeStatus changes the status of an account.
func (a *Auth) ChangeStatus(ctx context.Context, request *ssov1.ChangeStatusRequest) (*ssov1.ChangeStatusResponse, error) {
	const op = "Auth.ChangeStatus"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", request.GetAccountId()),
		slog.Int64("new_status", int64(request.GetStatus())),
	)

	log.Info("attempting to change account status")

	modelStatus := request.GetStatus()

	err := a.accountSaver.UpdateStatus(ctx, request.GetAccountId(), models.AccountStatus(modelStatus))
	if err != nil {
		log.Error("failed to change status", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("status changed successfully")
	return &ssov1.ChangeStatusResponse{
		AccountId: request.GetAccountId(),
		Status:    modelStatus,
	}, nil
}

func (a *Auth) GetActiveSessions(ctx context.Context, request *ssov1.GetActiveAccountSessionsRequest) (*ssov1.GetActiveAccountSessionsResponse, error) {
	const op = "Auth.GetActiveAccountSessions"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", request.GetAccountId()),
	)

	log.Info("retrieving active sessions")

	sessions, err := a.sessionProvider.Sessions(ctx, request.GetAccountId())
	if err != nil {
		log.Error("failed to retrieve sessions", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("sessions retrieved successfully")

	var result []*ssov1.Session
	for _, session := range sessions {
		ssov1Session := &ssov1.Session{
			AccountId:        session.AccountID,
			Token:            session.Token,
			RefreshToken:     session.RefreshToken,
			UserAgent:        session.UserAgent,
			IpAddress:        session.IPAddress,
			ExpiresAt:        session.ExpiresAt.Unix(),
			RefreshExpiresAt: session.RefreshExpiresAt.Unix(),
			CreatedAt:        session.CreatedAt.Unix(),
			UpdatedAt:        session.UpdatedAt.Unix(),
			Revoked:          session.Revoked,
		}
		result = append(result, ssov1Session)
	}

	log.Info("sessions retrieved and converted successfully")

	return &ssov1.GetActiveAccountSessionsResponse{Sessions: result}, nil
}

func (a *Auth) RefreshSession(ctx context.Context, request *ssov1.RefreshAccountSessionRequest) (*ssov1.RefreshAccountSessionResponse, error) {
	const op = "Auth.RefreshAccountSession"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", request.GetAccountId()),
	)

	log.Info("attempting to get account")

	account, err := a.accountProvider.AccountById(ctx, request.GetAccountId())
	if err != nil {
		log.Error("invalid account id", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("attempting to get app")

	app, err := a.appProvider.App(ctx, account.AppId)
	if err != nil {
		log.Error("invalid app id", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("attempting to refresh session")

	session, err := a.sessionProvider.SessionByRefreshToken(ctx, request.GetRefreshToken())
	if err != nil {
		log.Error("invalid refresh token", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if session.RefreshExpiresAt.Before(time.Now()) {
		log.Info("refresh token expired")
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	newToken, err := jwt.NewToken(account, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate new token", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		log.Error("failed to generate new refresh token", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	expiresAt := time.Now().Add(a.refreshTokenTTL)

	sessionID, err := a.sessionSaver.SaveSession(ctx, request.GetAccountId(), "", "", newToken, newRefreshToken, expiresAt)
	if err != nil {
		log.Error("failed to update session tokens", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("session created", slog.String("session_id", sessionID))

	return &ssov1.RefreshAccountSessionResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt.Unix(),
	}, nil

}

// ValidateSession validates if the token is still active.
func (a *Auth) ValidateSession(ctx context.Context, request *ssov1.ValidateAccountSessionRequest) (*ssov1.ValidateAccountSessionResponse, error) {
	const op = "Auth.ValidateAccountSession"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("validating session")

	session, err := a.sessionProvider.Session(ctx, request.GetToken())
	if err != nil {
		log.Error("invalid token", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if session.ExpiresAt.Before(time.Now()) {
		log.Info("session expired")
		return &ssov1.ValidateAccountSessionResponse{
			Valid:     false,
			ExpiresAt: session.ExpiresAt.Unix(),
		}, nil
	}

	log.Info("session is valid")

	return &ssov1.ValidateAccountSessionResponse{
		Valid:     true,
		ExpiresAt: session.ExpiresAt.Unix(),
	}, nil
}

// RevokeSession revokes the session associated with the given token.
func (a *Auth) RevokeSession(ctx context.Context, request *ssov1.RevokeAccountSessionRequest) (*ssov1.RevokeAccountSessionResponse, error) {
	const op = "Auth.RevokeAccountSession"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("revoking session")

	err := a.sessionProvider.RevokeSession(ctx, request.GetToken())
	if err != nil {
		log.Error("failed to revoke session", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("session revoked successfully")
	return &ssov1.RevokeAccountSessionResponse{Success: true}, nil
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AccountSaver interface {
	SaveAccount(ctx context.Context, email string, passHash []byte, role models.AccountRole, status models.AccountStatus, appId int32) (uid int64, err error)
	UpdatePassword(ctx context.Context, accountId int64, newPassHash []byte) (err error)
	UpdateStatus(ctx context.Context, accountId int64, status models.AccountStatus) (err error)
}

type AccountProvider interface {
	AccountByEmail(ctx context.Context, email string) (models.Account, error)
	AccountById(ctx context.Context, accountId int64) (models.Account, error)
	IsAdmin(ctx context.Context, accountId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (models.App, error)
}

type AppSaver interface {
	SaveApp(ctx context.Context, appName string, secret string, redirectUrl string) (uid int64, err error)
}

type SessionSaver interface {
	SaveSession(ctx context.Context, accountId int64, userAgent string, ipAddress string, token string, refreshToken string, expiresAt time.Time) (sessionID string, err error)
	RevokeSession(ctx context.Context, token string) (err error)
}

type SessionProvider interface {
	Sessions(ctx context.Context, accountId int64) ([]models.Session, error)
	Session(ctx context.Context, token string) (models.Session, error)
	SessionByRefreshToken(ctx context.Context, refreshToken string) (models.Session, error)
	RevokeSession(ctx context.Context, token string) (err error)
}

func New(
	log *slog.Logger,
	accountSaver AccountSaver,
	accountProvider AccountProvider,
	appProvider AppProvider,
	appSaver AppSaver,
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
		appSaver:        appSaver,
		sessionSaver:    sessionSaver,
		sessionProvider: sessionProvider,
		tokenTTL:        tokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func generateRefreshToken() (string, error) {
	const tokenSize = 32
	token := make([]byte, tokenSize)

	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(token), nil
}

// GetActiveAccountSessions retrieves all active sessions for the given account ID.
func (a *Auth) GetActiveAccountSessions(ctx context.Context, accountID int64) ([]*ssov1.Session, error) {
	const op = "Auth.GetActiveAccountSessions"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", accountID),
	)

	log.Info("retrieving active sessions")

	sessions, err := a.sessionProvider.Sessions(ctx, accountID)
	if err != nil {
		log.Error("failed to retrieve sessions", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("sessions retrieved successfully")

	var result []*ssov1.Session
	for _, session := range sessions {
		ssov1Session := &ssov1.Session{
			AccountId:        session.AccountID,
			Token:            session.Token,
			RefreshToken:     session.RefreshToken,
			UserAgent:        session.UserAgent,
			IpAddress:        session.IPAddress,
			ExpiresAt:        session.ExpiresAt.Unix(),
			RefreshExpiresAt: session.RefreshExpiresAt.Unix(),
			CreatedAt:        session.CreatedAt.Unix(),
			UpdatedAt:        session.UpdatedAt.Unix(),
			Revoked:          session.Revoked,
		}
		result = append(result, ssov1Session)
	}

	log.Info("sessions retrieved and converted successfully")

	return result, nil
}

// RefreshAccountSession refreshes the account session by generating a new token and refresh token.
func (a *Auth) RefreshAccountSession(ctx context.Context, accountID int64, refreshToken string, userAgent string, ipAddress string) (string, string, int64, error) {
	const op = "Auth.RefreshAccountSession"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("account_id", accountID),
	)

	log.Info("attempting to get account")

	account, err := a.accountProvider.AccountById(ctx, accountID)
	if err != nil {
		log.Error("invalid account id", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("attempting to get app")

	app, err := a.appProvider.App(ctx, account.AppId)
	if err != nil {
		log.Error("invalid app id", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("attempting to refresh session")

	session, err := a.sessionProvider.SessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Error("invalid refresh token", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	if session.RefreshExpiresAt.Before(time.Now()) {
		log.Info("refresh token expired")
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	newToken, err := jwt.NewToken(account, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate new token", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		log.Error("failed to generate new refresh token", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	expiresAt := time.Now().Add(a.refreshTokenTTL)

	sessionID, err := a.sessionSaver.SaveSession(ctx, accountID, userAgent, ipAddress, newToken, newRefreshToken, expiresAt)
	if err != nil {
		log.Error("failed to update session tokens", sl.Err(err))
		return "", "", 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("session created", slog.String("session_id", sessionID))

	return newToken, newRefreshToken, expiresAt.Unix(), nil
}
