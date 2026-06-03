"""TLS configuration and certificate validation tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from security.tls_config import load_tls_configuration, validate_certificates


class TestTLSConfiguration(unittest.TestCase):
    """Validate TLS config loading and certificate presence checks."""

    def test_load_tls_configuration_has_expected_keys(self) -> None:
        config = load_tls_configuration()
        self.assertIn("ca_certificate", config)
        self.assertIn("server_certificate", config)
        self.assertIn("server_key", config)
        self.assertIn("client_certificate", config)
        self.assertIn("client_key", config)

    def test_validate_certificates_false_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertFalse(validate_certificates(temp_dir))

    def test_validate_certificates_true_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for filename in ("ca.crt", "server.crt", "server.key", "client.crt", "client.key"):
                (directory / filename).write_text("dummy", encoding="utf-8")
            self.assertTrue(validate_certificates(directory))


if __name__ == "__main__":
    unittest.main()
