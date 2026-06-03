"""End-to-end tests for the valid vote flow."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from database.seed_data import DEMO_VOTERS, seed_demo_voters
from security.hashing import generate_payload
from server.database import get_voter_by_rfid, initialize_database, get_vote_results
from server.vote_verifier import process_vote


class TestVoteFlow(unittest.TestCase):
    """Check that a valid vote is accepted and written to the database."""

    def setUp(self) -> None:
        """Prepare a fresh temporary database for each test.

        Parameters:
            None.

        Returns:
            None.
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "flow.db"
        initialize_database(self.db_path)
        seed_demo_voters(self.db_path)

    def tearDown(self) -> None:
        """Remove the temporary database after the test.

        Parameters:
            None.

        Returns:
            None.
        """
        self.temp_dir.cleanup()

    def test_valid_vote_is_accepted(self) -> None:
        """A valid payload should be accepted and persisted.

        Parameters:
            None.

        Returns:
            None.
        """
        voter_id = DEMO_VOTERS[0]["rfid_id"]
        payload = generate_payload(voter_id, "A", "booth01")
        result = process_vote(payload, ip_address="127.0.0.1", db_path=str(self.db_path))
        self.assertEqual(result["status"], "accepted")
        voter = get_voter_by_rfid(voter_id, self.db_path)
        self.assertEqual(voter["has_voted"], 1)
        results = get_vote_results(self.db_path)
        self.assertEqual(results["total_votes"], 1)


if __name__ == "__main__":
    unittest.main()
