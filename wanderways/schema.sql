-- WanderWays Travel Portal - SQLite schema
-- Recreated from scratch by `flask --app wanderways init-db`.

DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    phone         TEXT,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'agent', 'customer')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE bookings (
    id            INTEGER PRIMARY KEY,           -- sequential ids: easy to guess
    booking_ref   TEXT    NOT NULL UNIQUE,
    customer_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    agent_id      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    destination   TEXT    NOT NULL,
    hotel         TEXT    NOT NULL,
    depart_date   TEXT    NOT NULL,              -- ISO 8601 (YYYY-MM-DD)
    return_date   TEXT    NOT NULL,
    travellers    INTEGER NOT NULL CHECK (travellers BETWEEN 1 AND 9),
    total_price   REAL    NOT NULL CHECK (total_price >= 0),
    status        TEXT    NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'confirmed', 'cancelled')),
    passport_no   TEXT    NOT NULL,              -- sensitive (sample data only)
    payment_last4 TEXT    NOT NULL,              -- sensitive (sample data only)
    notes         TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_bookings_customer ON bookings (customer_id);
CREATE INDEX idx_bookings_agent    ON bookings (agent_id);
