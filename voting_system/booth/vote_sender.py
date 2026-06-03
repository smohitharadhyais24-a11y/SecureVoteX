"""Vote packaging and sending helpers for the booth simulator."""
from __future__ import annotations

import logging
from typing import Any

from config.config import (
    DEFAULT_SOURCE_IP,
    BOOTH_ID,
    NETWORK_MODE,
)
from booth.mqtt_client import BoothMqttClient
from security.hashing import generate_payload
from server.vote_verifier import process_vote

logger = logging.getLogger(__name__)

def _publish_payload(payload: dict[str, Any]) -> bool:
    """Attempt to publish a payload to the MQTT broker.

    Parameters:
        payload: The vote payload dictionary.

    Returns:
        True if the publish attempt succeeds, otherwise False.
    """
    client = BoothMqttClient(booth_id=str(payload.get("booth_id", BOOTH_ID)))
    if not client.connect():
        logger.warning("MQTT client connection failed; publish skipped")
        return False
    try:
        response = client.submit_vote(payload)
        return response.get("status") == "accepted"
    finally:
        client.disconnect()


def send_vote_payload(payload: dict[str, Any], persist_locally_on_failure: bool = True, db_path: str | None = None) -> dict[str, Any]:
    """Send a prepared payload to MQTT and fall back to local storage if needed.

    Parameters:
        payload: The vote payload dictionary.
        persist_locally_on_failure: Whether to save the vote locally when MQTT is unavailable.
        db_path: Optional database path override.

    Returns:
        A dictionary describing the transport and verification result.
    """
    published = _publish_payload(payload) if NETWORK_MODE == "MQTT" else False
    result: dict[str, Any] = {
        "payload": payload,
        "transport": "mqtt" if published else "simulation-local",
        "published": published,
    }
    if NETWORK_MODE == "SIMULATION" or (not published and persist_locally_on_failure):
        result["local_result"] = process_vote(payload, ip_address=DEFAULT_SOURCE_IP, db_path=db_path)
    return result


def send_vote(
    voter_id: str,
    candidate: str,
    booth_id: str,
    persist_locally_on_failure: bool = True,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Create a vote payload and send it through the available transport.

    Parameters:
        voter_id: The voter's RFID identifier.
        candidate: The selected candidate code.
        booth_id: The booth identifier.
        persist_locally_on_failure: Whether to save the vote locally if MQTT fails.
        db_path: Optional database path override.

    Returns:
        A dictionary describing the transport result.
    """
    payload = generate_payload(voter_id, candidate, booth_id)
    logger.info("Prepared payload for voter_id=%s candidate=%s", voter_id, candidate)
    return send_vote_payload(payload, persist_locally_on_failure=persist_locally_on_failure, db_path=db_path)
