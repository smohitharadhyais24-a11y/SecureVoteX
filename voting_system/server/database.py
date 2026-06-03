"""SQLite database helpers for the voting system.

This module owns schema initialization, voter records, vote insertion, and
security audit logging. Every query uses parameterized SQL statements.
"""
from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from config.config import DATABASE_PATH, SCHEMA_PATH

logger = logging.getLogger(__name__)


def _resolve_path(db_path: str | Path | None = None) -> Path:
    """Return the database path that should be used for the current operation.

    Parameters:
        db_path: Optional override for the SQLite database file.

    Returns:
        The resolved database path.
    """
    return Path(db_path) if db_path is not None else DATABASE_PATH


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Create a SQLite connection with sensible defaults.

    Parameters:
        db_path: Optional override for the SQLite database file.

    Returns:
        An open SQLite connection object.
    """
    path = _resolve_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path: str | Path | None = None, schema_path: str | Path | None = None) -> None:
    """Create all tables and indexes from the SQL schema file.

    Parameters:
        db_path: Optional override for the SQLite database file.
        schema_path: Optional override for the schema file.

    Returns:
        None.
    """
    resolved_db_path = _resolve_path(db_path)
    resolved_schema_path = Path(schema_path) if schema_path is not None else SCHEMA_PATH
    try:
        schema_sql = resolved_schema_path.read_text(encoding="utf-8")
        with closing(get_connection(resolved_db_path)) as connection:
            connection.executescript(schema_sql)
            # Lightweight migration path for older Phase 1 DBs.
            audit_columns = {row["name"] for row in connection.execute("PRAGMA table_info(audit_log)").fetchall()}
            if "severity" not in audit_columns:
                connection.execute("ALTER TABLE audit_log ADD COLUMN severity TEXT DEFAULT 'INFO'")
            connection.commit()
        logger.info("Database initialized at %s", resolved_db_path)
    except Exception:
        logger.exception("Failed to initialize database at %s", resolved_db_path)
        raise


def insert_voter(rfid_id: str, name: str, fingerprint_id: int, db_path: str | Path | None = None) -> bool:
    """Insert a voter if the RFID card is not already registered.

    Parameters:
        rfid_id: Unique RFID identifier.
        name: Voter full name.
        fingerprint_id: Fingerprint template slot number.
        db_path: Optional override for the SQLite database file.

    Returns:
        True when a new voter was inserted, otherwise False.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute(
                """
                INSERT INTO voters (rfid_id, name, fingerprint_id, has_voted, registered_at, voted_at)
                VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP, NULL)
                """,
                (rfid_id, name, fingerprint_id),
            )
            connection.commit()
            inserted = cursor.rowcount > 0
            logger.info("Inserted voter %s (%s)", rfid_id, name)
            return inserted
    except sqlite3.IntegrityError:
        logger.info("Skipped duplicate voter %s", rfid_id)
        return False
    except Exception:
        logger.exception("Failed to insert voter %s", rfid_id)
        raise


def get_voter_by_rfid(rfid_id: str, db_path: str | Path | None = None) -> dict[str, Any] | None:
    """Fetch a single voter record by RFID identifier.

    Parameters:
        rfid_id: Unique RFID identifier.
        db_path: Optional override for the SQLite database file.

    Returns:
        A dictionary when the voter exists, otherwise None.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            row = connection.execute("SELECT * FROM voters WHERE rfid_id = ?", (rfid_id,)).fetchone()
            return dict(row) if row is not None else None
    except Exception:
        logger.exception("Failed to fetch voter %s", rfid_id)
        raise


def get_all_voters(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return all registered voters ordered by RFID identifier.

    Parameters:
        db_path: Optional override for the SQLite database file.

    Returns:
        A list of voter dictionaries.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            rows = connection.execute("SELECT * FROM voters ORDER BY rfid_id").fetchall()
            return [dict(row) for row in rows]
    except Exception:
        logger.exception("Failed to fetch registered voters")
        raise


def get_voted_voters(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return all voters who have already cast a vote.

    Parameters:
        db_path: Optional override for the SQLite database file.

    Returns:
        A list of voter dictionaries.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            rows = connection.execute("SELECT * FROM voters WHERE has_voted = 1 ORDER BY voted_at DESC").fetchall()
            return [dict(row) for row in rows]
    except Exception:
        logger.exception("Failed to fetch voted voters")
        raise


def set_voter_as_voted(rfid_id: str, voted_at: str, db_path: str | Path | None = None) -> bool:
    """Mark a voter as having voted.

    Parameters:
        rfid_id: Unique RFID identifier.
        voted_at: Timestamp string for the vote.
        db_path: Optional override for the SQLite database file.

    Returns:
        True when a row was updated, otherwise False.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute(
                "UPDATE voters SET has_voted = 1, voted_at = ? WHERE rfid_id = ?",
                (voted_at, rfid_id),
            )
            connection.commit()
            updated = cursor.rowcount > 0
            logger.info("Marked voter %s as voted", rfid_id)
            return updated
    except Exception:
        logger.exception("Failed to mark voter %s as voted", rfid_id)
        raise


def record_vote(
    voter_id: str,
    candidate: str,
    booth_id: str,
    timestamp: str,
    payload_hash: str,
    is_verified: bool,
    db_path: str | Path | None = None,
) -> int:
    """Insert a vote record into the votes table.

    Parameters:
        voter_id: The voter's RFID identifier.
        candidate: The selected candidate code.
        booth_id: The booth identifier.
        timestamp: The vote timestamp string.
        payload_hash: The SHA-256 hash string for the payload.
        is_verified: Whether the vote hash was verified successfully.
        db_path: Optional override for the SQLite database file.

    Returns:
        The inserted vote ID.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute(
                """
                INSERT INTO votes (voter_id, candidate, booth_id, timestamp, hash, is_verified)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (voter_id, candidate, booth_id, timestamp, payload_hash, int(is_verified)),
            )
            connection.commit()
            vote_id = int(cursor.lastrowid)
            logger.info("Recorded vote %s for voter %s", vote_id, voter_id)
            return vote_id
    except Exception:
        logger.exception("Failed to record vote for voter %s", voter_id)
        raise


def record_audit_log(
    event_type: str,
    rfid_id: str | None,
    details: str,
    timestamp: str,
    ip_address: str | None,
    db_path: str | Path | None = None,
    severity: str = "INFO",
) -> int:
    """Insert a security audit log entry.

    Parameters:
        event_type: The audit event classification.
        rfid_id: Optional RFID identifier connected to the event.
        details: Human-readable description of what happened.
        timestamp: Timestamp string for the event.
        ip_address: Optional source IP address.
        db_path: Optional override for the SQLite database file.

    Returns:
        The inserted audit log ID.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_log (event_type, rfid_id, details, timestamp, ip_address, severity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_type, rfid_id, details, timestamp, ip_address, severity),
            )
            connection.commit()
            log_id = int(cursor.lastrowid)
            logger.info("Recorded audit event %s for rfid_id=%s", event_type, rfid_id)
            return log_id
    except Exception:
        logger.exception("Failed to record audit event %s", event_type)
        raise


def get_last_sequence(voter_id: str, db_path: str | Path | None = None) -> int:
    """Return the last recorded sequence number for a voter (0 when none)."""
    try:
        with closing(get_connection(db_path)) as connection:
            row = connection.execute("SELECT last_sequence FROM vote_sequence WHERE voter_id = ?", (voter_id,)).fetchone()
            return int(row["last_sequence"]) if row is not None else 0
    except Exception:
        logger.exception("Failed to fetch last sequence for voter %s", voter_id)
        raise


def update_last_sequence(voter_id: str, sequence: int, db_path: str | Path | None = None) -> None:
    """Insert or update the last sequence number for a voter."""
    try:
        with closing(get_connection(db_path)) as connection:
            connection.execute(
                "INSERT INTO vote_sequence (voter_id, last_sequence) VALUES (?, ?) ON CONFLICT(voter_id) DO UPDATE SET last_sequence = excluded.last_sequence",
                (voter_id, sequence),
            )
            connection.commit()
            logger.info("Updated last_sequence for %s to %s", voter_id, sequence)
    except Exception:
        logger.exception("Failed to update last sequence for voter %s", voter_id)
        raise


def booth_exists(booth_id: str, db_path: str | Path | None = None) -> bool:
    """Check whether a booth is registered."""
    try:
        with closing(get_connection(db_path)) as connection:
            row = connection.execute("SELECT booth_id FROM booths WHERE booth_id = ?", (booth_id,)).fetchone()
            return row is not None
    except Exception:
        # If the booths table does not exist yet, initialize the schema and retry once.
        logger.warning("Booth existence check failed for %s; attempting to initialize schema and retry", booth_id)
        try:
            initialize_database(db_path=db_path)
            with closing(get_connection(db_path)) as connection:
                row = connection.execute("SELECT booth_id FROM booths WHERE booth_id = ?", (booth_id,)).fetchone()
                return row is not None
        except Exception:
            logger.exception("Failed to check booth existence %s after initialization", booth_id)
            raise


def insert_booth(booth_id: str, booth_name: str, location: str | None = None, status: str = "INACTIVE", db_path: str | Path | None = None) -> bool:
    """Insert a booth record if missing."""
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO booths (booth_id, booth_name, location, status, registered_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                (booth_id, booth_name, location, status),
            )
            connection.commit()
            inserted = cursor.rowcount > 0
            if inserted:
                logger.info("Inserted booth %s (%s)", booth_id, booth_name)
            return inserted
    except Exception:
        logger.exception("Failed to insert booth %s", booth_id)
        raise


def create_admin(username: str, password_hash: str, role: str = "ELECTION_OFFICER", db_path: str | Path | None = None) -> int:
    """Create an admin user record.

    Returns the created admin_id.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute(
                "INSERT INTO admins (username, password_hash, role, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (username, password_hash, role),
            )
            connection.commit()
            admin_id = int(cursor.lastrowid)
            logger.info("Created admin %s with role %s", username, role)
            return admin_id
    except sqlite3.IntegrityError:
        logger.info("Admin %s already exists", username)
        raise
    except Exception:
        logger.exception("Failed to create admin %s", username)
        raise


def authenticate_admin(username: str, password_hash: str, db_path: str | Path | None = None) -> bool:
    """Authenticate an admin by username and password hash."""
    try:
        with closing(get_connection(db_path)) as connection:
            row = connection.execute("SELECT password_hash FROM admins WHERE username = ?", (username,)).fetchone()
            if row is None:
                return False
            return hmac_compare(password_hash, row["password_hash"])
    except Exception:
        logger.exception("Failed to authenticate admin %s", username)
        raise


def change_admin_password(username: str, new_password_hash: str, db_path: str | Path | None = None) -> bool:
    """Change an admin's password hash."""
    try:
        with closing(get_connection(db_path)) as connection:
            cursor = connection.execute("UPDATE admins SET password_hash = ? WHERE username = ?", (new_password_hash, username))
            connection.commit()
            return cursor.rowcount > 0
    except Exception:
        logger.exception("Failed to change password for admin %s", username)
        raise


def get_election_status(db_path: str | Path | None = None) -> str:
    """Return the current election status string (ACTIVE, INACTIVE, etc).

    If multiple rows exist, return the most recent.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            row = connection.execute("SELECT status FROM election_config ORDER BY election_id DESC LIMIT 1").fetchone()
            return str(row["status"]) if row is not None else "INACTIVE"
    except Exception:
        logger.exception("Failed to fetch election status")
        raise


def update_component_status(component: str, status: str, message: str | None = None, db_path: str | Path | None = None) -> None:
    """Insert or update a component's system health status."""
    try:
        with closing(get_connection(db_path)) as connection:
            connection.execute(
                "INSERT INTO system_health (component, status, last_seen, message) VALUES (?, ?, CURRENT_TIMESTAMP, ?) ON CONFLICT(component) DO UPDATE SET status = excluded.status, last_seen = excluded.last_seen, message = excluded.message",
                (component, status, message),
            )
            connection.commit()
            logger.info("Updated system health for %s to %s", component, status)
    except Exception:
        logger.exception("Failed to update system health for %s", component)
        raise


def get_system_health(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return the current system health records."""
    try:
        with closing(get_connection(db_path)) as connection:
            rows = connection.execute("SELECT * FROM system_health ORDER BY component").fetchall()
            return [dict(row) for row in rows]
    except Exception:
        logger.exception("Failed to fetch system health")
        raise


def get_dashboard_statistics(db_path: str | Path | None = None) -> dict[str, Any]:
    """Return enhanced dashboard statistics for the admin UI."""
    try:
        with closing(get_connection(db_path)) as connection:
            total_registered = connection.execute("SELECT COUNT(*) as total FROM voters").fetchone()["total"]
            total_votes = connection.execute("SELECT COUNT(*) as total FROM votes").fetchone()["total"]
            rejected = connection.execute("SELECT COUNT(*) as total FROM audit_log WHERE event_type != 'Vote Cast'").fetchone()["total"]
            tampered = connection.execute("SELECT COUNT(*) as total FROM audit_log WHERE event_type = 'Tampered Packet'").fetchone()["total"]
            replay = connection.execute("SELECT COUNT(*) as total FROM audit_log WHERE event_type = 'REPLAY_ATTACK'").fetchone()["total"]
            double_votes = connection.execute("SELECT COUNT(*) as total FROM audit_log WHERE event_type = 'Double Vote Attempt'").fetchone()["total"]
            return {
                "total_registered_voters": total_registered,
                "total_votes_cast": total_votes,
                "turnout_percentage": (total_votes / total_registered * 100) if total_registered > 0 else 0.0,
                "rejected_votes": rejected,
                "tampered_packets": tampered,
                "replay_attacks": replay,
                "double_vote_attempts": double_votes,
            }
    except Exception:
        logger.exception("Failed to fetch dashboard statistics")
        raise


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time compare wrapper for strings."""
    try:
        import hmac as _hmac

        return _hmac.compare_digest(a, b)
    except Exception:
        logger.exception("Failed to compare HMAC strings")
        raise


def get_vote_results(db_path: str | Path | None = None) -> dict[str, Any]:
    """Return summary statistics for dashboard display.

    Parameters:
        db_path: Optional override for the SQLite database file.

    Returns:
        A dictionary with vote totals and candidate counts.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            total_voters = connection.execute("SELECT COUNT(*) AS total FROM voters").fetchone()["total"]
            total_votes = connection.execute("SELECT COUNT(*) AS total FROM votes").fetchone()["total"]
            candidate_rows = connection.execute(
                "SELECT candidate, COUNT(*) AS count FROM votes GROUP BY candidate ORDER BY candidate"
            ).fetchall()
            candidate_counts = {row["candidate"]: row["count"] for row in candidate_rows}
            audit_rows = connection.execute(
                "SELECT event_type, COUNT(*) AS count FROM audit_log GROUP BY event_type ORDER BY event_type"
            ).fetchall()
            audit_counts = {row["event_type"]: row["count"] for row in audit_rows}
            return {
                "total_voters": total_voters,
                "total_votes": total_votes,
                "candidate_counts": candidate_counts,
                "audit_counts": audit_counts,
            }
    except Exception:
        logger.exception("Failed to load vote results")
        raise


def get_recent_audit_logs(limit: int = 20, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return the most recent audit log entries.

    Parameters:
        limit: Maximum number of audit rows to return.
        db_path: Optional override for the SQLite database file.

    Returns:
        A list of audit log dictionaries.
    """
    try:
        with closing(get_connection(db_path)) as connection:
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC, log_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception:
        logger.exception("Failed to fetch recent audit logs")
        raise
