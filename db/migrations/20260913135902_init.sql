-- migrate:up

CREATE TABLE auth_user (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT TRUE CHECK (enabled IN (FALSE, TRUE)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- migrate:down

DROP TABLE auth_user;
