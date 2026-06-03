"""Network/API flow tests for auth and vote submit endpoints."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from database.seed_data import DEMO_VOTERS, seed_demo_voters
from security.hashing import generate_payload
from server.app import create_app
from server.database import initialize_database


class TestNetworkFlow(unittest.TestCase):
    """Validate HTTP auth and vote transport endpoints."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "network.db"
        initialize_database(self.db_path)
        seed_demo_voters(self.db_path)
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_rfid_auth_endpoint(self) -> None:
        rfid = DEMO_VOTERS[0]["rfid_id"]
        response = self.client.post("/api/auth/rfid", json={"rfid": rfid})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["registered"])

    def test_vote_submit_endpoint(self) -> None:
        voter_id = DEMO_VOTERS[1]["rfid_id"]
        payload = generate_payload(voter_id, "A", "booth01")
        response = self.client.post("/api/vote/submit", json=payload)
        self.assertIn(response.status_code, (200, 400))
        body = response.get_json()
        self.assertIn("success", body)

    def test_dashboard_stats_endpoint(self) -> None:
        response = self.client.get("/api/dashboard/stats")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("total_voters", body)
        self.assertIn("replay_attacks", body)


if __name__ == "__main__":
    unittest.main()
