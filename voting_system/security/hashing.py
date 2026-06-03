"""SHA-256 hashing helpers for vote payloads.

The functions in this module create deterministic hashes for vote payloads,
validate hashes using timing-safe comparison, and build complete payload
objects ready to send over MQTT or to process locally.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from config.config import SHA256_SECRET_SALT
from config.config import SECRET_KEY

logger = logging.getLogger(__name__)


def generate_vote_hash(voter_id: str, candidate: str, booth_id: str, timestamp: str, salt: str) -> str:
    """Generate a deterministic SHA-256 hash for a vote payload.

    Parameters:
        voter_id: The voter's RFID identifier.
        candidate: The selected candidate code.
        booth_id: The booth identifier.
        timestamp: The timestamp string used in the payload.
        salt: The secret salt applied before hashing.

    Returns:
        The SHA-256 hex digest string.
    """
    payload_string = f"{voter_id}|{candidate}|{booth_id}|{timestamp}|{salt}"
    digest = hashlib.sha256(payload_string.encode("utf-8")).hexdigest()
    logger.debug("Generated vote hash for voter_id=%s candidate=%s booth_id=%s", voter_id, candidate, booth_id)
    return digest


def verify_vote_hash(
    voter_id: str,
    candidate: str,
    booth_id: str,
    timestamp: str,
    received_hash: str,
    salt: str,
) -> bool:
    """Verify a received vote hash against the recalculated hash.

    Parameters:
        voter_id: The voter's RFID identifier.
        candidate: The selected candidate code.
        booth_id: The booth identifier.
        timestamp: The timestamp string used in the payload.
        received_hash: The hash value received from the payload.
        salt: The secret salt applied before hashing.

    Returns:
        True when the hashes match, otherwise False.
    """
    expected_hash = generate_vote_hash(voter_id, candidate, booth_id, timestamp, salt)
    result = hmac.compare_digest(expected_hash, received_hash)
    logger.info("Vote hash verification for voter_id=%s result=%s", voter_id, result)
    return result


def generate_hmac_signature(payload: dict, secret_key: str) -> str:
    """Generate an HMAC-SHA256 signature for a vote payload.

    The signature covers the canonical fields: voter_id, candidate, booth_id,
    timestamp and sequence_number. The caller must ensure these fields exist.

    Parameters:
        payload: The vote payload dictionary.
        secret_key: The HMAC secret key.

    Returns:
        Hexadecimal HMAC-SHA256 signature string.
    """
    parts = [
        str(payload.get("voter_id", "")),
        str(payload.get("candidate", "")),
        str(payload.get("booth_id", "")),
        str(payload.get("timestamp", "")),
        str(payload.get("sequence_number", "")),
    ]
    message = "|".join(parts).encode("utf-8")
    signature = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()
    logger.debug("Generated HMAC signature for voter_id=%s sequence=%s", payload.get("voter_id"), payload.get("sequence_number"))
    return signature


def verify_hmac_signature(payload: dict, signature: str, secret_key: str) -> bool:
    """Verify an HMAC-SHA256 signature for a payload using timing-safe comparison.

    Parameters:
        payload: The vote payload dictionary.
        signature: The hex signature received in the payload.
        secret_key: The HMAC secret key.

    Returns:
        True if the signature matches, False otherwise.
    """
    expected = generate_hmac_signature(payload, secret_key)
    result = hmac.compare_digest(expected, signature)
    logger.info("HMAC signature verification attempt for voter_id=%s sequence=%s result=%s",
                payload.get("voter_id"), payload.get("sequence_number"), result)
    return result


def generate_payload(voter_id: str, candidate: str, booth_id: str, sequence_number: int = 1) -> dict[str, Any]:
    """Create a complete vote payload with timestamp, hash, and message ID.

    Parameters:
        voter_id: The voter's RFID identifier.
        candidate: The selected candidate code.
        booth_id: The booth identifier.

    Returns:
        A dictionary containing the complete vote payload.
    """
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload: dict[str, Any] = {
        "message_id": str(uuid4()),
        "voter_id": voter_id,
        "candidate": candidate,
        "booth_id": booth_id,
        "timestamp": timestamp,
        "sequence_number": sequence_number,
    }
    signature = generate_hmac_signature(payload, SECRET_KEY)
    payload["signature"] = signature
    # Maintain backwards compat: keep `hash` field populated with signature as well
    payload["hash"] = signature
    logger.debug("Generated vote payload for voter_id=%s", voter_id)
    return payload
