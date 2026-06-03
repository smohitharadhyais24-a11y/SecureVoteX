"""Vote payload verification and local processing logic."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from config.config import DEFAULT_SOURCE_IP, SHA256_SECRET_SALT, VALID_CANDIDATES, SECRET_KEY
from security.hashing import verify_hmac_signature
from server.database import (
    get_voter_by_rfid,
    get_dashboard_statistics,
    record_audit_log,
    record_vote,
    set_voter_as_voted,
    get_last_sequence,
    update_last_sequence,
    booth_exists,
    get_election_status,
)
from server.socketio_handler import emit_dashboard_update, emit_new_vote

logger = logging.getLogger(__name__)


def validate_vote_payload(payload: dict[str, Any]) -> tuple[bool, str]:
    """Check that a vote payload contains the required fields and values.

    Parameters:
        payload: The incoming vote payload dictionary.

    Returns:
        A tuple of (is_valid, error_message).
    """
    required_fields = ("voter_id", "candidate", "booth_id", "timestamp", "sequence_number", "signature")
    missing_fields = [field for field in required_fields if field not in payload]
    if missing_fields:
        message = f"Missing required fields: {', '.join(missing_fields)}"
        logger.warning(message)
        return False, message

    if payload["candidate"] not in VALID_CANDIDATES:
        message = f"Invalid candidate value: {payload['candidate']}"
        logger.warning(message)
        return False, message

    return True, "Payload structure is valid"


def verify_vote_payload(payload: dict[str, Any], secret_key: str = SECRET_KEY, db_path: str | None = None) -> tuple[bool, str]:
    """Verify the hash for a complete vote payload.

    Parameters:
        payload: The incoming vote payload dictionary.
        salt: The secret salt used during hash generation.

    Returns:
        A tuple of (is_verified, message).
    """
    is_valid, message = validate_vote_payload(payload)
    if not is_valid:
        return False, message
    # Verify signature using HMAC
    signature = str(payload.get("signature", ""))
    verified = verify_hmac_signature(payload, signature, secret_key)
    # Log the verification attempt in the audit log as INFO/CRITICAL
    try:
        # Ensure audit logs go to the provided database when db_path is supplied
        record_audit_log("SIGNATURE_VERIFICATION", payload.get("voter_id"), f"Signature verification result: {verified}", payload.get("timestamp"), None, db_path, severity="INFO")
    except Exception:
        logger.exception("Failed to record signature verification audit log")

    # If a legacy `hash` field is present but does not match the computed signature,
    # consider the payload tampered (tests expect this behavior when only `hash` is modified).
    provided_hash = str(payload.get("hash", ""))
    if provided_hash and provided_hash != signature:
        logger.warning("Payload hash mismatch detected for voter_id=%s", payload["voter_id"])
        return False, "TAMPERED_PACKET"

    if verified:
        logger.info("Vote payload signature verified for voter_id=%s", payload["voter_id"])
        return True, "Signature verification successful"

    logger.warning("Vote payload tamper detected for voter_id=%s", payload["voter_id"])
    return False, "TAMPERED_PACKET"


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string.

    Parameters:
        None.

    Returns:
        The current UTC timestamp string.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def process_vote(payload: dict[str, Any], ip_address: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    """Validate, verify, and persist a vote payload.

    Parameters:
        payload: The incoming vote payload dictionary.
        ip_address: Optional source IP address for the audit log.
        db_path: Optional override for the SQLite database file.

    Returns:
        A dictionary describing the processing outcome.
    """
    source_ip = ip_address or DEFAULT_SOURCE_IP
    try:
        is_valid, message = validate_vote_payload(payload)
        if not is_valid:
            record_audit_log("AUTH_FAILED", payload.get("voter_id"), message, _now_iso(), source_ip, db_path, severity="WARNING")
            return {"status": "rejected", "event_type": "AUTH_FAILED", "message": message, "payload": payload}

        voter = get_voter_by_rfid(payload["voter_id"], db_path=db_path)
        if voter is None:
            details = "Voter is not registered in the database"
            record_audit_log("REJECTED_UNREGISTERED", payload["voter_id"], details, _now_iso(), source_ip, db_path, severity="WARNING")
            return {
                "status": "rejected",
                "event_type": "REJECTED_UNREGISTERED",
                "message": details,
                "payload": payload,
            }

        if int(voter["has_voted"]) == 1:
            details = "This voter has already cast a vote"
            record_audit_log("Double Vote Attempt", payload["voter_id"], details, _now_iso(), source_ip, db_path, severity="WARNING")
            return {
                "status": "rejected",
                "event_type": "REJECTED_DOUBLE",
                "message": details,
                "payload": payload,
            }

        # Ensure booth is valid (use same db when provided)
        if not booth_exists(payload.get("booth_id"), db_path=db_path):
            details = "Invalid or unknown booth"
            record_audit_log("REJECTED_INVALID_BOOTH", payload["voter_id"], details, _now_iso(), source_ip, db_path, severity="WARNING")
            return {"status": "rejected", "event_type": "REJECTED_INVALID_BOOTH", "message": details, "payload": payload}

        # Ensure election is active
        election_status = get_election_status(db_path=db_path)
        if election_status != "ACTIVE":
            details = f"Election not active (status={election_status})"
            record_audit_log("REJECTED_ELECTION_INACTIVE", payload["voter_id"], details, _now_iso(), source_ip, db_path, severity="WARNING")
            return {"status": "rejected", "event_type": "REJECTED_ELECTION_INACTIVE", "message": details, "payload": payload}

        verified, verification_message = verify_vote_payload(payload, SECRET_KEY, db_path=db_path)
        if not verified:
            # Tampered or invalid signature
            record_audit_log("Tampered Packet", payload["voter_id"], verification_message, _now_iso(), source_ip, db_path, severity="CRITICAL")
            return {
                "status": "rejected",
                "event_type": "TAMPER_DETECTED",
                "message": verification_message,
                "payload": payload,
            }

        # Replay protection: sequence number must be increasing
        try:
            seq = int(payload.get("sequence_number", 0))
            last_seq = get_last_sequence(payload["voter_id"], db_path=db_path)
            if seq <= last_seq:
                details = "Duplicate or lower sequence number detected"
                record_audit_log("REPLAY_ATTACK", payload["voter_id"], details, _now_iso(), source_ip, db_path, severity="CRITICAL")
                return {"status": "rejected", "event_type": "REPLAY_ATTACK", "message": details, "payload": payload}
        except Exception:
            logger.exception("Failed to validate sequence number for voter %s", payload.get("voter_id"))
            record_audit_log("REPLAY_ATTACK", payload.get("voter_id"), "Sequence validation error", _now_iso(), source_ip, db_path, severity="CRITICAL")
            return {"status": "rejected", "event_type": "REPLAY_ATTACK", "message": "Sequence validation error", "payload": payload}

        vote_id = record_vote(
            voter_id=payload["voter_id"],
            candidate=payload["candidate"],
            booth_id=payload["booth_id"],
            timestamp=payload["timestamp"],
            payload_hash=payload.get("signature") or payload.get("hash"),
            is_verified=True,
            db_path=db_path,
        )
        # update sequence after successful record
        try:
            update_last_sequence(payload["voter_id"], int(payload.get("sequence_number", 0)), db_path=db_path)
        except Exception:
            logger.exception("Failed to update vote sequence for voter %s", payload.get("voter_id"))
        set_voter_as_voted(payload["voter_id"], payload["timestamp"], db_path=db_path)
        record_audit_log(
            "VOTE_CAST",
            payload["voter_id"],
            f"Vote {vote_id} recorded successfully for candidate {payload['candidate']}",
            _now_iso(),
            source_ip,
            db_path,
        )
        try:
            emit_new_vote({"vote_id": vote_id, "voter_id": payload["voter_id"], "candidate": payload["candidate"], "booth_id": payload["booth_id"]})
            emit_dashboard_update(get_dashboard_statistics(db_path=db_path))
        except Exception:
            logger.exception("Failed to emit realtime dashboard updates")
        logger.info("Accepted vote_id=%s for voter_id=%s", vote_id, payload["voter_id"])
        return {
            "status": "accepted",
            "event_type": "VOTE_CAST",
            "message": f"Vote recorded for candidate {payload['candidate']}",
            "vote_id": vote_id,
            "payload": payload,
        }
    except Exception as exc:
        logger.exception("Failed to process vote for payload=%s", payload)
        try:
            record_audit_log("AUTH_FAILED", payload.get("voter_id"), str(exc), _now_iso(), source_ip, db_path)
        except Exception:
            logger.exception("Failed to record fallback audit event after vote processing error")
        return {"status": "error", "event_type": "AUTH_FAILED", "message": str(exc), "payload": payload}
