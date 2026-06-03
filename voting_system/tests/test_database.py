"""Unit tests for SQLite database operations."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from database.seed_data import DEMO_VOTERS, seed_demo_voters
from server.database import get_all_voters, get_voter_by_rfid, initialize_database, record_audit_log, record_vote, set_voter_as_voted


class TestDatabase(unittest.TestCase):
    """Exercise the core database helpers using a temporary SQLite file."""

    def setUp(self) -> None:
        """Create a fresh temporary database for each test.

        Parameters:
            None.

        Returns:
            None.
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_voting.db"
        initialize_database(self.db_path)
        seed_demo_voters(self.db_path)

    def tearDown(self) -> None:
        """Clean up the temporary database directory.

        Parameters:
            None.

        Returns:
            None.
        """
        self.temp_dir.cleanup()

    def test_seed_inserts_ten_voters(self) -> None:
        """The seed script should create exactly ten demo voters.

        Parameters:
            None.

        Returns:
            None.
        """
        voters = get_all_voters(self.db_path)
        self.assertEqual(len(voters), len(DEMO_VOTERS))

    def test_duplicate_seed_is_skipped(self) -> None:
        """Running the seeder twice should not create duplicates.

        Parameters:
            None.

        Returns:
            None.
        """
        seed_demo_voters(self.db_path)
        voters = get_all_voters(self.db_path)
        self.assertEqual(len(voters), len(DEMO_VOTERS))

    def test_vote_and_audit_helpers_work(self) -> None:
        """Database helpers should record votes, updates, and audit events.

        Parameters:
            None.

        Returns:
            None.
        """
        voter_id = DEMO_VOTERS[0]["rfid_id"]
        vote_id = record_vote(voter_id, "A", "booth01", "2026-06-03T10:00:00+00:00", "hash", True, self.db_path)
        self.assertGreater(vote_id, 0)
        self.assertTrue(set_voter_as_voted(voter_id, "2026-06-03T10:00:00+00:00", self.db_path))
        voter = get_voter_by_rfid(voter_id, self.db_path)
        self.assertIsNotNone(voter)
        self.assertEqual(voter["has_voted"], 1)
        log_id = record_audit_log("VOTE_CAST", voter_id, "Vote stored", "2026-06-03T10:00:00+00:00", "127.0.0.1", self.db_path)
        self.assertGreater(log_id, 0)


if __name__ == "__main__":
    unittest.main()
