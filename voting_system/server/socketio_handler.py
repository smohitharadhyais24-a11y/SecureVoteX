"""SocketIO infrastructure for future live updates.

This module creates a `SocketIO` instance and provides small helpers for
emitting events. Full real-time functionality will be implemented in later
phases; for now this file just prepares the wiring so future work can emit
`new_vote`, `dashboard_update`, and `system_health_update` events.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import Flask
try:  # pragma: no cover - optional dependency during some test envs
    from flask_socketio import SocketIO
except Exception:  # pragma: no cover
    SocketIO = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

socketio: Any = None


_active_clients = 0


def get_active_clients_count() -> int:
    """Return the number of active SocketIO client connections."""
    return _active_clients


def emit_active_clients() -> None:
    """Broadcast current active clients count to all clients."""
    if socketio is None:
        return
    try:
        socketio.emit("active_clients", {"count": _active_clients})
    except Exception:
        logger.exception("Failed to emit active_clients event")


def init_socketio(app: Flask, async_mode: str | None = None) -> SocketIO:
    """Initialize and return a SocketIO instance attached to the Flask app.

    Parameters:
        app: The Flask application instance.
        async_mode: Optional async mode for SocketIO (eventlet/gevent/threading).

    Returns:
        The created SocketIO instance.
    """
    global socketio
    if SocketIO is None:
        logger.warning("flask-socketio is not installed; realtime emits are disabled")
        return None  # type: ignore[return-value]
    if socketio is None:
        socketio = SocketIO(app, async_mode=async_mode, cors_allowed_origins="*")
        logger.info("SocketIO initialized with async_mode=%s", async_mode)

        @socketio.on("connect")
        def handle_connect() -> None:
            global _active_clients
            _active_clients += 1
            emit_active_clients()
            logger.info("SocketIO client connected. Active clients: %s", _active_clients)

        @socketio.on("disconnect")
        def handle_disconnect() -> None:
            global _active_clients
            _active_clients = max(0, _active_clients - 1)
            emit_active_clients()
            logger.info("SocketIO client disconnected. Active clients: %s", _active_clients)
    else:
        socketio.init_app(app)
        logger.info("SocketIO re-initialized for new app instance")

    return socketio



def emit_new_vote(payload: dict[str, Any]) -> None:
    """Emit a `new_vote` event (no-op when SocketIO is not initialized)."""
    if socketio is None:
        logger.debug("SocketIO not initialized; skipping new_vote emit")
        return
    try:
        socketio.emit("new_vote", payload)
    except Exception:
        logger.exception("Failed to emit new_vote event")


def emit_dashboard_update(stats: dict[str, Any]) -> None:
    """Emit a `dashboard_update` event with the latest statistics."""
    if socketio is None:
        logger.debug("SocketIO not initialized; skipping dashboard_update emit")
        return
    try:
        socketio.emit("dashboard_update", stats)
    except Exception:
        logger.exception("Failed to emit dashboard_update event")


def emit_system_health_update(health: dict[str, Any]) -> None:
    """Emit a `system_health_update` event with health payload."""
    if socketio is None:
        logger.debug("SocketIO not initialized; skipping system_health_update emit")
        return
    try:
        socketio.emit("system_health_update", health)
    except Exception:
        logger.exception("Failed to emit system_health_update event")


def emit_auth_event(event_type: str, details: str, is_success: bool) -> None:
    """Emit a live authentication or vote event for the Live Authentication Monitor."""
    if socketio is None:
        logger.debug("SocketIO not initialized; skipping auth_event emit")
        return
    try:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        socketio.emit("auth_event", {
            "timestamp": timestamp,
            "event_type": event_type,
            "details": details,
            "is_success": is_success
        })
    except Exception:
        logger.exception("Failed to emit auth_event")

