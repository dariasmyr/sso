CREATE TABLE IF NOT EXISTS accounts
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email        TEXT NOT NULL UNIQUE,
    pass_hash    BYTEA NOT NULL,
    status       TEXT NOT NULL,
    app_id       BIGINT NOT NULL REFERENCES apps(id),
    role         TEXT NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_email ON accounts (email);

CREATE TABLE IF NOT EXISTS apps
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name      TEXT NOT NULL UNIQUE,
    secret    TEXT NOT NULL UNIQUE,
    redirect_url TEXT
);


CREATE TABLE IF NOT EXISTS sessions
(
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id        BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token             TEXT NOT NULL UNIQUE,
    refresh_token     TEXT NOT NULL,
    user_agent        TEXT,
    ip_address        TEXT,
    expires_at        TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP NOT NULL,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked           BOOLEAN NOT NULL DEFAULT FALSE
    );

CREATE INDEX IF NOT EXISTS idx_account_id ON sessions (account_id);
