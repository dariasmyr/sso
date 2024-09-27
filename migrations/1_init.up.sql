CREATE TABLE IF NOT EXISTS accounts
(
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email        TEXT NOT NULL UNIQUE,
    pass_hash    BYTEA NOT NULL,
    status       INTEGER NOT NULL, -- AccountStatus (0 - ACTIVE, 1 - INACTIVE, 2 - DELETED)
    app_id       BIGINT REFERENCES apps(id),
    roles        INTEGER[] NOT NULL, -- AccountRoles (0 - USER, 1 - ADMIN)
    CONSTRAINT valid_status CHECK (status IN (0, 1, 2))
    );

CREATE INDEX IF NOT EXISTS idx_email ON accounts (email);

CREATE TABLE IF NOT EXISTS apps
(
    id        BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name      TEXT NOT NULL UNIQUE,
    secret    TEXT NOT NULL UNIQUE
);


CREATE TABLE IF NOT EXISTS sessions
(
    id                BIGSERIAL PRIMARY KEY,
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
