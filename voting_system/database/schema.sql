PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_name TEXT NOT NULL,
    party_name TEXT NOT NULL,
    symbol_path TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS voters (
    rfid_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    fingerprint_id INTEGER,
    has_voted BOOLEAN NOT NULL DEFAULT 0,
    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    voted_at TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS votes (
    vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id TEXT NOT NULL,
    candidate TEXT NOT NULL,
    booth_id TEXT,
    timestamp TIMESTAMP NOT NULL,
    hash TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (voter_id) REFERENCES voters (rfid_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    rfid_id TEXT,
    details TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    severity TEXT NOT NULL DEFAULT 'INFO'
);


-- Replay protection: track last sequence number per voter
CREATE TABLE IF NOT EXISTS vote_sequence (
    voter_id TEXT PRIMARY KEY,
    last_sequence INTEGER DEFAULT 0,
    FOREIGN KEY (voter_id) REFERENCES voters (rfid_id)
);


-- Booth registration and management
CREATE TABLE IF NOT EXISTS booths (
    booth_id TEXT PRIMARY KEY,
    booth_name TEXT NOT NULL,
    location TEXT,
    status TEXT NOT NULL DEFAULT 'INACTIVE',
    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- Admin users for dashboard and system management
CREATE TABLE IF NOT EXISTS admins (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- Election configuration
CREATE TABLE IF NOT EXISTS election_config (
    election_id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_name TEXT NOT NULL,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'INACTIVE'
);


-- System health monitoring
CREATE TABLE IF NOT EXISTS system_health (
    component TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_voters_rfid_id ON voters (rfid_id);
CREATE INDEX IF NOT EXISTS idx_voters_registered_at ON voters (registered_at);
CREATE INDEX IF NOT EXISTS idx_voters_voted_at ON voters (voted_at);
CREATE INDEX IF NOT EXISTS idx_votes_voter_id ON votes (voter_id);
CREATE INDEX IF NOT EXISTS idx_votes_timestamp ON votes (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_rfid_id ON audit_log (rfid_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
