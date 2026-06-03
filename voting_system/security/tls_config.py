"""TLS configuration helpers for the MQTT broker and client certificates."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from config.config import CERTIFICATES_DIR, MQTT_TLS_PORT


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
        "client_certificate": str(directory / "client.crt"),
        "client_key": str(directory / "client.key"),
    }
