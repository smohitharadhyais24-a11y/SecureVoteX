"""Seed the SQLite database with demo voter records.

The script creates the schema if needed and inserts ten pre-registered voters
for use in the booth simulator and automated tests.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from config.config import DATABASE_PATH, SCHEMA_PATH
from server.database import (
    initialize_database,
    insert_voter,
    get_all_voters,
    insert_booth,
    create_admin,
    update_last_sequence,
)
from config.config import BOOTH_ID
from server.database import get_connection
import hashlib

logger = logging.getLogger(__name__)

DEMO_VOTERS: list[dict[str, object]] = [
    {"rfid_id": "A1:B2:C3:D4", "name": "Ravi Kumar", "fingerprint_id": 1},
    {"rfid_id": "E5:F6:G7:H8", "name": "Priya Sharma", "fingerprint_id": 2},
    {"rfid_id": "I9:J0:K1:L2", "name": "Arjun Rao", "fingerprint_id": 3},
    {"rfid_id": "M3:N4:O5:P6", "name": "Sneha Patil", "fingerprint_id": 4},
    {"rfid_id": "Q7:R8:S9:T0", "name": "Kiran Nair", "fingerprint_id": 5},
    {"rfid_id": "U1:V2:W3:X4", "name": "Deepa Menon", "fingerprint_id": 6},
    {"rfid_id": "Y5:Z6:A7:B8", "name": "Vikram Singh", "fingerprint_id": 7},
    {"rfid_id": "C9:D0:E1:F2", "name": "Ananya Iyer", "fingerprint_id": 8},
    {"rfid_id": "G3:H4:I5:J6", "name": "Rohit Verma", "fingerprint_id": 9},
    {"rfid_id": "K7:L8:M9:N0", "name": "Meera Joshi", "fingerprint_id": 10},
]


def seed_demo_voters(db_path: str | Path | None = None) -> int:
    """Create the database schema and insert the ten demo voters.

    Parameters:
        db_path: Optional override for the SQLite database file.

    Returns:
        The total number of voters present after seeding.
    """
    target_db_path = Path(db_path) if db_path is not None else DATABASE_PATH
    initialize_database(target_db_path, SCHEMA_PATH)

    print("Seeding demo voters...")
    for voter in DEMO_VOTERS:
        inserted = insert_voter(
            str(voter["rfid_id"]),
            str(voter["name"]),
            int(voter["fingerprint_id"]),
            target_db_path,
        )
        if inserted:
            print(
                f"Inserted voter: {voter['name']} | RFID: {voter['rfid_id']} | Fingerprint ID: {voter['fingerprint_id']}"
            )
        else:
            print(f"Skipped duplicate voter: {voter['name']} | RFID: {voter['rfid_id']}")

    total_voters = len(get_all_voters(target_db_path))
    current_total = len(get_all_voters(target_db_path))
    # Generate additional auto voters to reach 100 total only for the real project DB
    # (when db_path is None). Tests that pass an explicit db_path expect only the
    # ten demo voters to be inserted.
    if db_path is None:
        needed = 100 - current_total
        if needed > 0:
            print(f"Adding {needed} auto-generated voters to reach 100 total")
            start_index = current_total + 1
            for i in range(start_index, 100 + 1):
                code = f"AUTO{i:03d}"
                rfid = f"RFID-{code}"
                name = f"Auto Voter {i:03d}"
                fingerprint = i
                inserted = insert_voter(rfid, name, fingerprint, target_db_path)
                if inserted:
                    update_last_sequence(rfid, 0, target_db_path)
    total_voters = len(get_all_voters(target_db_path))
    print(f"Total voters registered: {total_voters}")
    logger.info("Database seeding complete with %s total voters", total_voters)
    # Ensure default booth exists (idempotent)
    try:
        from contextlib import closing

        with closing(get_connection(target_db_path)) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO booths (booth_id, booth_name, location, status, registered_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                ("BOOTH001", "Main Voting Booth", "Lab Room", "ACTIVE"),
            )
            # Also ensure the configured booth id exists for compatibility with existing tests
            if BOOTH_ID != "BOOTH001":
                conn.execute(
                    "INSERT OR IGNORE INTO booths (booth_id, booth_name, location, status, registered_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (BOOTH_ID, "Local Booth", "Local", "ACTIVE"),
                )
            conn.commit()
            # Verify and print
            row = conn.execute("SELECT booth_id, booth_name, location, status FROM booths WHERE booth_id = ?", ("BOOTH001",)).fetchone()
            if row:
                print(f"Ensured booth: {row['booth_id']} | {row['booth_name']} | {row['location']} | {row['status']}")
            else:
                print("Failed to ensure default booth BOOTH001")
    except Exception:
        logger.exception("Failed to ensure default booth")

    # Ensure default admin exists (idempotent)
    try:
        from contextlib import closing
        import bcrypt

        password = "admin123"
        # Generate secure bcrypt password hash
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        with closing(get_connection(target_db_path)) as conn:
            # Check if admin already exists
            row = conn.execute("SELECT password_hash FROM admins WHERE username = ?", ("admin",)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO admins (username, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    ("admin", password_hash, "SUPER_ADMIN", "ACTIVE"),
                )
                conn.commit()
                print("Created default admin 'admin' with bcrypt password hashing")
            else:
                print("Default admin 'admin' already exists")
    except Exception:
        logger.exception("Failed to create default admin")

    # Ensure default candidates exist (idempotent)
    try:
        from contextlib import closing
        with closing(get_connection(target_db_path)) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO candidates (candidate_id, candidate_name, party_name, symbol_path, status) VALUES (?, ?, ?, ?, ?)",
                (1, "Candidate A", "Democratic Party", "/static/uploads/symbols/candidate_a.png", "ACTIVE")
            )
            conn.execute(
                "INSERT OR IGNORE INTO candidates (candidate_id, candidate_name, party_name, symbol_path, status) VALUES (?, ?, ?, ?, ?)",
                (2, "Candidate B", "Republican Party", "/static/uploads/symbols/candidate_b.png", "ACTIVE")
            )
            conn.execute(
                "INSERT OR IGNORE INTO candidates (candidate_id, candidate_name, party_name, symbol_path, status) VALUES (?, ?, ?, ?, ?)",
                (3, "Candidate C", "Independent Party", "/static/uploads/symbols/candidate_c.png", "ACTIVE")
            )
            conn.commit()
            print("Ensured default candidates A, B, and C exist in database")
    except Exception:
        logger.exception("Failed to seed default candidates")

    # Ensure default election exists (idempotent)
    try:
        from contextlib import closing

        with closing(get_connection(target_db_path)) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO election_config (election_name, start_time, end_time, status) VALUES (?, ?, ?, ?)",
                ("College Student Council Election 2026", "2026-06-03T09:00:00", "2026-06-03T17:00:00", "ACTIVE"),
            )
            conn.commit()
            row = conn.execute("SELECT election_name, status FROM election_config WHERE election_name = ? ORDER BY election_id DESC LIMIT 1", ("College Student Council Election 2026",)).fetchone()
            if row:
                print(f"Ensured election: {row['election_name']} | status={row['status']}")
            else:
                print("Failed to ensure default election config")
    except Exception:
        logger.exception("Failed to insert default election config")
    return total_voters


def main() -> None:
    """Run the seeding workflow as a command-line entry point.

    Parameters:
        None.

    Returns:
        None.
    """
    try:
        seed_demo_voters()
    except Exception:
        logger.exception("Seeding failed")
        raise


if __name__ == "__main__":
    main()
