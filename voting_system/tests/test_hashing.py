"""Unit tests for vote hashing helpers."""
from __future__ import annotations

import unittest

from security.hashing import generate_payload, generate_vote_hash, verify_vote_hash


class TestHashing(unittest.TestCase):
    """Verify deterministic hash generation and safe comparison."""

    def test_generate_vote_hash_is_deterministic(self) -> None:
        """The same inputs should always produce the same hash.

        Parameters:
            None.

        Returns:
            None.
        """
        first = generate_vote_hash("A1:B2:C3:D4", "A", "booth01", "2026-06-03T10:00:00+00:00", "salt")
        second = generate_vote_hash("A1:B2:C3:D4", "A", "booth01", "2026-06-03T10:00:00+00:00", "salt")
        self.assertEqual(first, second)

    def test_verify_vote_hash_returns_true_for_match(self) -> None:
        """A valid hash should verify successfully.

        Parameters:
            None.

        Returns:
            None.
        """
        timestamp = "2026-06-03T10:00:00+00:00"
        payload_hash = generate_vote_hash("A1:B2:C3:D4", "B", "booth01", timestamp, "salt")
        self.assertTrue(verify_vote_hash("A1:B2:C3:D4", "B", "booth01", timestamp, payload_hash, "salt"))

    def test_generate_payload_contains_required_fields(self) -> None:
        """Generated payloads should contain all vote fields.

        Parameters:
            None.

        Returns:
            None.
        """
        payload = generate_payload("A1:B2:C3:D4", "C", "booth01")
        self.assertIn("timestamp", payload)
        self.assertIn("hash", payload)
        self.assertEqual(payload["candidate"], "C")


if __name__ == "__main__":
    unittest.main()
