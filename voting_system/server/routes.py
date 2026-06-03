"""Flask routes for the voting system dashboard and API."""
from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, render_template, request

from config.config import ELECTION_NAME
from server.database import get_all_voters, get_recent_audit_logs, get_vote_results
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


def register_routes(app: Any) -> None:
    """Attach all Flask routes to an application instance.

    Parameters:
        app: The Flask application object.

    Returns:
        None.
    """
    app.register_blueprint(routes)
