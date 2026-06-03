"""Flask routes for the voting system dashboard and API."""
from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, render_template, request

from config.config import ELECTION_NAME
from server.database import get_all_voters, get_recent_audit_logs, get_vote_results, get_voter_by_rfid, get_dashboard_statistics
from server.vote_verifier import process_vote

logger = logging.getLogger(__name__)

routes = Blueprint("routes", __name__)


@routes.route("/")
def index() -> str:
    """Render the live dashboard page.

    Parameters:
        None.

    Returns:
        Rendered HTML response as a string.
    """
    return render_template("index.html", election_name=ELECTION_NAME)


@routes.route("/api/results")
def api_results():
    """Return voting summary data for the dashboard.

    Parameters:
        None.

    Returns:
        A JSON response containing election results.
    """
    try:
        return jsonify(get_vote_results())
    except Exception as exc:  # pragma: no cover - defensive API path
        logger.exception("Failed to generate results payload")
        return jsonify({"status": "error", "message": str(exc)}), 500


@routes.route("/api/voters")
def api_voters():
    """Return the full registered voter list.

    Parameters:
        None.

    Returns:
        A JSON response containing voter records.
    """
    try:
        return jsonify({"voters": get_all_voters()})
    except Exception as exc:  # pragma: no cover - defensive API path
        logger.exception("Failed to generate voters payload")
        return jsonify({"status": "error", "message": str(exc)}), 500


@routes.route("/api/audit")
def api_audit():
    """Return recent audit log rows.

    Parameters:
        None.

    Returns:
        A JSON response containing recent audit events.
    """
    try:
        return jsonify({"audit_log": get_recent_audit_logs()})
    except Exception as exc:  # pragma: no cover - defensive API path
        logger.exception("Failed to generate audit payload")
        return jsonify({"status": "error", "message": str(exc)}), 500


@routes.route("/api/process-vote", methods=["POST"])
def api_process_vote():
    """Process a vote payload directly from HTTP for testing.

    Parameters:
        None.

    Returns:
        A JSON response describing the vote verification result.
    """
    try:
        payload = request.get_json(force=True, silent=False)
        if not isinstance(payload, dict):
            return jsonify({"status": "error", "message": "JSON body must be an object"}), 400
        result = process_vote(payload, ip_address=request.remote_addr)
        status_code = 200 if result.get("status") == "accepted" else 400
        return jsonify(result), status_code
    except Exception as exc:  # pragma: no cover - defensive API path
        logger.exception("Failed to process HTTP vote")
        return jsonify({"status": "error", "message": str(exc)}), 500


@routes.route("/api/auth/rfid", methods=["POST"])
def api_auth_rfid():
    """Authenticate RFID and return voter identity metadata."""
    try:
        payload = request.get_json(force=True, silent=False)
        if not isinstance(payload, dict):
            return jsonify({"registered": False, "message": "JSON body must be an object"}), 400
        rfid = str(payload.get("rfid", ""))
        if not rfid:
            return jsonify({"registered": False, "message": "Missing rfid"}), 400

        voter = get_voter_by_rfid(rfid)
        if voter is None:
            return jsonify({"registered": False})

        return jsonify(
            {
                "registered": True,
                "name": voter["name"],
                "fingerprint_id": voter["fingerprint_id"],
            }
        )
    except Exception as exc:
        logger.exception("RFID auth API failed")
        return jsonify({"registered": False, "message": str(exc)}), 500


@routes.route("/api/auth/fingerprint", methods=["POST"])
def api_auth_fingerprint():
    """Verify fingerprint id against the RFID-owned voter record."""
    try:
        payload = request.get_json(force=True, silent=False)
        if not isinstance(payload, dict):
            return jsonify({"verified": False, "message": "JSON body must be an object"}), 400

        rfid = str(payload.get("rfid", ""))
        fingerprint_id = payload.get("fingerprint_id")
        if not rfid or fingerprint_id is None:
            return jsonify({"verified": False, "message": "rfid and fingerprint_id are required"}), 400

        voter = get_voter_by_rfid(rfid)
        if voter is None:
            return jsonify({"verified": False})

        verified = int(voter["fingerprint_id"]) == int(fingerprint_id)
        return jsonify({"verified": verified})
    except Exception as exc:
        logger.exception("Fingerprint auth API failed")
        return jsonify({"verified": False, "message": str(exc)}), 500


@routes.route("/api/vote/submit", methods=["POST"])
def api_vote_submit():
    """Receive a vote payload and run full verification/persistence."""
    try:
        payload = request.get_json(force=True, silent=False)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "message": "JSON body must be an object"}), 400
        result = process_vote(payload, ip_address=request.remote_addr)
        if result.get("status") == "accepted":
            return jsonify({"success": True, "vote_id": result.get("vote_id")})
        return jsonify({"success": False, "event_type": result.get("event_type"), "message": result.get("message")}), 400
    except Exception as exc:
        logger.exception("Vote submit API failed")
        return jsonify({"success": False, "message": str(exc)}), 500


@routes.route("/api/dashboard/stats")
def api_dashboard_stats():
    """Return admin dashboard statistics."""
    try:
        stats = get_dashboard_statistics()
        return jsonify(
            {
                "total_voters": stats.get("total_registered_voters", 0),
                "turnout": stats.get("turnout_percentage", 0.0),
                "candidate_counts": get_vote_results().get("candidate_counts", {}),
                "rejected_votes": stats.get("rejected_votes", 0),
                "replay_attacks": stats.get("replay_attacks", 0),
                "tampered_packets": stats.get("tampered_packets", 0),
            }
        )
    except Exception as exc:
        logger.exception("Dashboard stats API failed")
        return jsonify({"status": "error", "message": str(exc)}), 500


def register_routes(app: Any) -> None:
    """Attach all Flask routes to an application instance.

    Parameters:
        app: The Flask application object.

    Returns:
        None.
    """
    app.register_blueprint(routes)
