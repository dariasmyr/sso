// Main migrations init script: go run ./cmd/migrator --storage-path=./storage/sso.db --migrations-path=./migrations
// Test migrations init script: go run ./cmd/migrator --storage-path=./storage/sso.db --migrations-path=./tests/migrations --migrations-table=migrations_test
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"time"
)

type Storage struct {
	db *sql.DB
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) IsAdmin(ctx context.Context, accountId int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	stmt, err := s.db.Prepare("SELECT role FROM accounts WHERE id = ?")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var role string
	err = stmt.QueryRowContext(ctx, accountId).Scan(&role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrAccountNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	isAdmin := role == "admin"

	return isAdmin, nil
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveAccount(ctx context.Context, email string, passHash []byte, role models.AccountRole, status models.AccountStatus, appID int32) (int64, error) {
	const op = "storage.sqlite.SaveAccount"

	stmt, err := s.db.Prepare(`
		INSERT INTO accounts (email, pass_hash, status, app_id, role) 
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, email, passHash, status, appID, role)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrAccountExists)
		}

		return 0, fmt.Errorf("%s: %w", op, storage.ErrAccountExists) // TODO: remove hack for custom error validation (the above condition is not working as the type error from sqliute cannot be compared with custom storage.ErrAccountExists)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) Account(ctx context.Context, email string) (models.Account, error) {
	const op = "storage.sqlite.Account"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM users WHERE email = ?")
	if err != nil {
		return models.Account{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var account models.Account
	err = row.Scan(&account.ID, &account.Email, &account.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Account{}, fmt.Errorf("%s: %w", op, storage.ErrAccountNotFound)
		}

		return models.Account{}, fmt.Errorf("%s: %w", op, err)
	}

	return account, nil
}

func (s *Storage) App(ctx context.Context, appId int32) (models.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, appId)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (s *Storage) SaveApp(ctx context.Context, appName string, secret string, redirectUrl string) (int64, error) {
	const op = "storage.sqlite.SaveApp"

	stmt, err := s.db.Prepare(`
		INSERT INTO app (app_name, secret, redirect_url) 
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, appName, secret, redirectUrl)
	if err != nil {
		var sqliteErr sqlite3.Error

		if errors.As(err, &sqliteErr) && errors.Is(sqliteErr, sqlite3.ErrConstraintUnique) {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrAppExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) AccountByEmail(ctx context.Context, email string) (models.Account, error) {
	const op = "storage.sqlite.AccountByEmail"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash, role, status, app_id FROM accounts WHERE email = ?")
	if err != nil {
		return models.Account{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var account models.Account
	err = stmt.QueryRowContext(ctx, email).Scan(&account.ID, &account.Email, &account.PassHash, &account.Role, &account.Status, &account.AppId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Account{}, fmt.Errorf("%s: %w", op, storage.ErrAccountNotFound)
		}
		return models.Account{}, fmt.Errorf("%s: %w", op, err)
	}

	return account, nil
}

func (s *Storage) AccountById(ctx context.Context, accountId int64) (models.Account, error) {
	const op = "storage.sqlite.AccountById"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash, role, status, app_id FROM accounts WHERE id = ?")
	if err != nil {
		return models.Account{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var account models.Account
	err = stmt.QueryRowContext(ctx, accountId).Scan(&account.ID, &account.Email, &account.PassHash, &account.Role, &account.Status, &account.AppId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Account{}, fmt.Errorf("%s: %w", op, storage.ErrAccountNotFound)
		}
		return models.Account{}, fmt.Errorf("%s: %w", op, err)
	}

	return account, nil
}

func (s *Storage) UpdatePassword(ctx context.Context, accountId int64, newPassHash []byte) error {
	const op = "storage.sqlite.UpdatePassword"

	stmt, err := s.db.Prepare("UPDATE accounts SET pass_hash = ? WHERE id = ?")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, newPassHash, accountId)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) UpdateStatus(ctx context.Context, accountId int64, status models.AccountStatus) error {
	const op = "storage.sqlite.UpdateStatus"

	stmt, err := s.db.Prepare("UPDATE accounts SET status = ? WHERE id = ?")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, status, accountId)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) SaveSession(ctx context.Context, accountId int64, userAgent, ipAddress, token, refreshToken string, expiresAt time.Time) (string, error) {
	const op = "storage.sqlite.SaveSession"

	stmt, err := s.db.Prepare(`
		INSERT INTO sessions (account_id, token, refresh_token, user_agent, ip_address, expires_at, refresh_expires_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	refreshExpiresAt := expiresAt.Add(7 * 24 * time.Hour)

	_, err = stmt.ExecContext(ctx, accountId, token, refreshToken, userAgent, ipAddress, expiresAt, refreshExpiresAt)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (s *Storage) Sessions(ctx context.Context, accountId int64) ([]models.Session, error) {
	const op = "storage.sqlite.Sessions"

	stmt, err := s.db.Prepare(`
		SELECT id, account_id, token, refresh_token, user_agent, ip_address, expires_at, refresh_expires_at, revoked 
		FROM sessions WHERE account_id = ? AND revoked = 0
	`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, accountId)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		var session models.Session
		err := rows.Scan(&session.ID, &session.AccountID, &session.Token, &session.RefreshToken, &session.UserAgent, &session.IPAddress, &session.ExpiresAt, &session.RefreshExpiresAt, &session.Revoked)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (s *Storage) Session(ctx context.Context, token string) (models.Session, error) {
	const op = "storage.sqlite.Session"

	stmt, err := s.db.Prepare(`
		SELECT id, account_id, token, refresh_token, user_agent, ip_address, expires_at, refresh_expires_at, revoked 
		FROM sessions WHERE token = ?
	`)
	if err != nil {
		return models.Session{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var session models.Session
	err = stmt.QueryRowContext(ctx, token).Scan(&session.ID, &session.AccountID, &session.Token, &session.RefreshToken, &session.UserAgent, &session.IPAddress, &session.ExpiresAt, &session.RefreshExpiresAt, &session.Revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Session{}, fmt.Errorf("%s: %w", op, storage.ErrSessionNotFound)
		}
		return models.Session{}, fmt.Errorf("%s: %w", op, err)
	}

	return session, nil
}

func (s *Storage) SessionByRefreshToken(ctx context.Context, refreshToken string) (models.Session, error) {
	const op = "storage.sqlite.SessionByRefreshToken"

	stmt, err := s.db.Prepare(`
		SELECT id, account_id, token, refresh_token, user_agent, ip_address, expires_at, refresh_expires_at, revoked 
		FROM sessions WHERE refresh_token = ?
	`)
	if err != nil {
		return models.Session{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var session models.Session
	err = stmt.QueryRowContext(ctx, refreshToken).Scan(&session.ID, &session.AccountID, &session.Token, &session.RefreshToken, &session.UserAgent, &session.IPAddress, &session.ExpiresAt, &session.RefreshExpiresAt, &session.Revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Session{}, fmt.Errorf("%s: %w", op, storage.ErrSessionNotFound)
		}
		return models.Session{}, fmt.Errorf("%s: %w", op, err)
	}

	return session, nil
}

func (s *Storage) RevokeSession(ctx context.Context, token string) error {
	const op = "storage.sqlite.RevokeSession"

	stmt, err := s.db.Prepare("UPDATE sessions SET revoked = 1 WHERE token = ?")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
