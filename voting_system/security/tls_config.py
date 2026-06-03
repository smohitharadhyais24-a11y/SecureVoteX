"""TLS configuration helpers for the MQTT broker and client certificates."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from config.config import CERTIFICATES_DIR, MQTT_TLS_PORT

logger = logging.getLogger(__name__)


def build_tls_config(certificates_dir: str | Path | None = None) -> dict[str, Any]:
    """Build a TLS configuration dictionary for later MQTT use.

    Parameters:
        certificates_dir: Optional override for the certificate directory.

    Returns:
        A dictionary containing certificate file paths and the TLS port.
    """
    directory = Path(certificates_dir) if certificates_dir is not None else CERTIFICATES_DIR
    return {
        "enabled": True,
        "port": MQTT_TLS_PORT,
        "ca_certificate": str(directory / "ca.crt"),
        "server_certificate": str(directory / "server.crt"),
        "server_key": str(directory / "server.key"),
        "client_certificate": str(directory / "client.crt"),
        "client_key": str(directory / "client.key"),
    }


def load_tls_configuration(certificates_dir: str | Path | None = None) -> dict[str, Any]:
    """Load TLS settings and normalize to absolute paths."""
    config = build_tls_config(certificates_dir)
    for key in ("ca_certificate", "server_certificate", "server_key", "client_certificate", "client_key"):
        config[key] = str(Path(config[key]).resolve())
    return config


def validate_certificates(certificates_dir: str | Path | None = None) -> bool:
    """Return True when all expected certificate files exist."""
    config = load_tls_configuration(certificates_dir)
    required = [
        config["ca_certificate"],
        config["server_certificate"],
        config["server_key"],
        config["client_certificate"],
        config["client_key"],
    ]
    missing = [path for path in required if not Path(path).exists()]
    if missing:
        logger.warning("Missing TLS certificate files: %s", missing)
        return False
    return True
