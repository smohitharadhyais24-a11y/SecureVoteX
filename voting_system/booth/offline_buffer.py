"""Offline buffering for vote payloads when the network/MQTT broker is unavailable.

The buffer persists votes to `buffered_votes.json` and will retry sending them
periodically. It keeps audit logs for buffering and delivery attempts.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from config.config import OFFLINE_BUFFER_PATH, DEFAULT_SOURCE_IP
from server.database import record_audit_log, get_connection
from booth.vote_sender import _publish_payload

logger = logging.getLogger(__name__)


class OfflineBuffer:
    """Simple file-backed buffer for vote payloads with automatic retry.

    Usage:
        buffer = OfflineBuffer()
        buffer.start()
        buffer.save_vote(payload)
        buffer.stop()
    """

    def __init__(self, path: Path | str | None = None, retry_interval: int = 10) -> None:
        self.path = Path(path) if path is not None else OFFLINE_BUFFER_PATH
        self.retry_interval = retry_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_buffer([])

    def _read_buffer(self) -> List[Dict[str, Any]]:
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return []

    def _write_buffer(self, items: List[Dict[str, Any]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2)
            fh.flush()
        tmp.replace(self.path)

    def save_vote(self, payload: Dict[str, Any]) -> None:
        """Persist a vote payload to the buffer and record an audit log."""
        items = self._read_buffer()
        items.append(payload)
        try:
            self._write_buffer(items)
            # Audit log
            record_audit_log("Offline Buffered Vote", payload.get("voter_id"), "Vote buffered locally due to network", payload.get("timestamp"), DEFAULT_SOURCE_IP, severity="INFO")
            logger.info("Saved vote to offline buffer for voter %s", payload.get("voter_id"))
        except Exception:
            logger.exception("Failed to save vote to offline buffer for voter %s", payload.get("voter_id"))

    def _retry_once(self) -> None:
        items = self._read_buffer()
        if not items:
            return
        remaining: List[Dict[str, Any]] = []
        for payload in items:
            try:
                ok = _publish_payload(payload)
                if ok:
                    # recorded by server when processed; add audit for delivery
                    record_audit_log("Offline Delivery", payload.get("voter_id"), "Buffered vote delivered to broker", payload.get("timestamp"), DEFAULT_SOURCE_IP, severity="INFO")
                    logger.info("Delivered buffered vote for voter %s", payload.get("voter_id"))
                else:
                    remaining.append(payload)
            except Exception:
                logger.exception("Error while retrying buffered vote for voter %s", payload.get("voter_id"))
                remaining.append(payload)
        # write remaining back
        try:
            self._write_buffer(remaining)
        except Exception:
            logger.exception("Failed to update offline buffer after retries")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._retry_once()
            except Exception:
                logger.exception("Offline buffer retry loop encountered an error")
            # wait with ability to stop sooner
            self._stop_event.wait(self.retry_interval)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Offline buffer started with interval %s seconds", self.retry_interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.retry_interval + 1)
            logger.info("Offline buffer stopped")


# Module-level convenience singleton
_buffer_singleton: OfflineBuffer | None = None


def get_offline_buffer() -> OfflineBuffer:
    global _buffer_singleton
    if _buffer_singleton is None:
        _buffer_singleton = OfflineBuffer()
    return _buffer_singleton
