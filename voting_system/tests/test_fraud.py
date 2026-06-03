"""Fraud scenario tests for duplicate and tampered votes."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from database.seed_data import DEMO_VOTERS, seed_demo_voters
from security.hashing import generate_payload
from server.database import initialize_database
from server.vote_verifier import process_vote


class TestFraudScenarios(unittest.TestCase):
    """Verify that fraud cases are rejected and logged."""

    def setUp(self) -> None:
        """Create a temporary database for each fraud test.

        Parameters:
            None.

        Returns:
            None.
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "fraud.db"
        initialize_database(self.db_path)
        seed_demo_voters(self.db_path)

    def tearDown(self) -> None:
        """Dispose of the temporary database directory.

        Parameters:
            None.

        Returns:
            None.
        """
        self.temp_dir.cleanup()

    def test_double_vote_is_rejected(self) -> None:
        """A second vote from the same voter should be rejected.

        Parameters:
            None.

        Returns:
            None.
        """
        voter_id = DEMO_VOTERS[1]["rfid_id"]
        first_payload = generate_payload(voter_id, "A", "booth01")
        first_result = process_vote(first_payload, ip_address="127.0.0.1", db_path=str(self.db_path))
        self.assertEqual(first_result["status"], "accepted")
        second_payload = generate_payload(voter_id, "B", "booth01")
        second_result = process_vote(second_payload, ip_address="127.0.0.1", db_path=str(self.db_path))
        self.assertEqual(second_result["event_type"], "REJECTED_DOUBLE")

    def test_tampered_packet_is_rejected(self) -> None:
        """A modified hash should trigger tamper detection.

        Parameters:
            None.

        Returns:
            None.
        """
        voter_id = DEMO_VOTERS[2]["rfid_id"]
        payload = generate_payload(voter_id, "C", "booth01")
        payload["hash"] = "f" * 64
        result = process_vote(payload, ip_address="127.0.0.1", db_path=str(self.db_path))
        self.assertEqual(result["event_type"], "TAMPER_DETECTED")


if __name__ == "__main__":
    unittest.main()
