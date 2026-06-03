"""Fingerprint sensor simulation helpers for the booth emulator."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def simulate_fingerprint_attempt(name: str, fingerprint_id: int, matched: bool = True) -> bool:
    """Print the fingerprint scanning flow for the simulator.

    Parameters:
        name: The voter's full name.
        fingerprint_id: The simulated fingerprint slot number.
        matched: Whether the simulated fingerprint check should succeed.

    Returns:
        True if the fingerprint matched, otherwise False.
    """
    print("[LCD] Place finger on sensor...")
    print(f"[SYSTEM] Checking fingerprint template slot {fingerprint_id} for {name}")
    if matched:
        print("[LCD] Fingerprint matched!")
        logger.info("Fingerprint match simulated for %s", name)
        return True

    print("[LCD] Fingerprint mismatch!")
    logger.info("Fingerprint mismatch simulated for %s", name)
    return False
