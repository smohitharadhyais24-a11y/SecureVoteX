"""Vote packaging and sending helpers for the booth simulator."""
from __future__ import annotations

import json
import logging
from typing import Any

from config.config import (
    DEFAULT_SOURCE_IP,
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_CLIENT_ID,
    MQTT_KEEPALIVE_SECONDS,
    MQTT_VOTE_TOPIC,
    SHA256_SECRET_SALT,
)
from security.hashing import generate_payload
from server.vote_verifier import process_vote

logger = logging.getLogger(__name__)

try:  # pragma: no cover - dependency may be absent during static checks
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover - fallback when dependency is unavailable
    mqtt = None


def _publish_payload(payload: dict[str, Any]) -> bool:
    """Attempt to publish a payload to the MQTT broker.

    Parameters:
        payload: The vote payload dictionary.

    Returns:
        True if the publish attempt succeeds, otherwise False.
    """
    if mqtt is None:
        logger.warning("paho-mqtt is unavailable; skipping MQTT publish")
        return False

    client = mqtt.Client(client_id=MQTT_CLIENT_ID)
    try:
        client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, MQTT_KEEPALIVE_SECONDS)
        client.loop_start()
        info = client.publish(MQTT_VOTE_TOPIC, json.dumps(payload), qos=0)
        info.wait_for_publish(timeout=MQTT_KEEPALIVE_SECONDS)
        client.loop_stop()
        client.disconnect()
        logger.info("Published vote payload to MQTT topic %s", MQTT_VOTE_TOPIC)
        return info.rc == 0
    except Exception:
        logger.exception("MQTT publish failed")
        return False


def send_vote_payload(payload: dict[str, Any], persist_locally_on_failure: bool = True, db_path: str | None = None) -> dict[str, Any]:
    """Send a prepared payload to MQTT and fall back to local storage if needed.

    Parameters:
        payload: The vote payload dictionary.
        persist_locally_on_failure: Whether to save the vote locally when MQTT is unavailable.
        db_path: Optional database path override.

    Returns:
        A dictionary describing the transport and verification result.
    """
    published = _publish_payload(payload)
    result: dict[str, Any] = {
        "payload": payload,
        "transport": "mqtt" if published else "local-fallback",
        "published": published,
    }
    if not published and persist_locally_on_failure:
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
