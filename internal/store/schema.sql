CREATE TABLE app_state (
    id          INTEGER PRIMARY KEY,
    generation  INTEGER NOT NULL DEFAULT 0
);

INSERT INTO app_state (id, generation) VALUES (1, 0);

CREATE TABLE subscriptions (
    id                TEXT PRIMARY KEY NOT NULL,
    name              TEXT NOT NULL UNIQUE,
    url               TEXT NOT NULL UNIQUE,
    refresh_interval  TEXT NOT NULL,
    last_attempt_at   TEXT,
    last_success_at   TEXT,
    last_error        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE nodes (
    id               TEXT PRIMARY KEY NOT NULL,
    subscription_id  TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    outbound_json    TEXT NOT NULL,
    latency_json     TEXT,
    ip_check_json    TEXT,
    UNIQUE (subscription_id, name)
);

PRAGMA user_version = 3;
