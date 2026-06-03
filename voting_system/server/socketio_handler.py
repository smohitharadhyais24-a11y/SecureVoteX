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
from flask_socketio import SocketIO

logger = logging.getLogger(__name__)

socketio: SocketIO | None = None


def init_socketio(app: Flask, async_mode: str | None = None) -> SocketIO:
    """Initialize and return a SocketIO instance attached to the Flask app.

    Parameters:
        app: The Flask application instance.
        async_mode: Optional async mode for SocketIO (eventlet/gevent/threading).

    Returns:
        The created SocketIO instance.
    """
    global socketio
    if socketio is None:
        socketio = SocketIO(app, async_mode=async_mode)
        logger.info("SocketIO initialized with async_mode=%s", async_mode)
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
