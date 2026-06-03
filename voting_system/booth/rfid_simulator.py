"""RFID simulation helpers for the ESP32 booth emulator."""
from __future__ import annotations

import logging
from typing import Any

from tabulate import tabulate

from server.database import get_all_voters

logger = logging.getLogger(__name__)


def list_registered_voters(db_path: str | None = None) -> list[dict[str, Any]]:
    """Return the registered voters for display in the simulator.

    Parameters:
        db_path: Optional database path override.

    Returns:
        A list of voter dictionaries.
    """
    voters = get_all_voters(db_path)
    logger.debug("Loaded %s registered voters for RFID simulator", len(voters))
    return voters


def format_voter_menu(voters: list[dict[str, Any]]) -> str:
    """Format the voter list as a readable terminal table.

    Parameters:
        voters: The registered voter dictionaries.

    Returns:
        A tabulated string for terminal output.
    """
    rows = [
        [index + 1, voter["name"], voter["rfid_id"], voter["fingerprint_id"], "Yes" if voter["has_voted"] else "No"]
        for index, voter in enumerate(voters)
    ]
    return tabulate(rows, headers=["#", "Name", "RFID", "Fingerprint", "Voted"], tablefmt="grid")


def get_voter_by_choice(voters: list[dict[str, Any]], choice: int) -> dict[str, Any]:
    """Return a voter from a 1-based selection index.

    Parameters:
        voters: The registered voter dictionaries.
        choice: The user-selected 1-based index.

    Returns:
        The matching voter dictionary.

    Raises:
        IndexError: If the selected index is out of range.
    """
    return voters[choice - 1]


def simulate_rfid_scan(rfid_id: str) -> None:
    """Print the RFID scan sequence used in the booth simulator.

    Parameters:
        rfid_id: The RFID identifier to display.

    Returns:
        None.
    """
    print("[LCD] Scanning RFID card...")
    print(f"[LCD] Card detected: {rfid_id}")
    logger.info("Simulated RFID scan for %s", rfid_id)
