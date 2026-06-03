"""MQTT subscriber that receives vote payloads from the booth simulator."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable

from config.config import (
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_CLIENT_ID,
    MQTT_KEEPALIVE_SECONDS,
    MQTT_VOTE_TOPIC,
)
from server.vote_verifier import process_vote

logger = logging.getLogger(__name__)

try:  # pragma: no cover - dependency may be absent during static checks
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover - fallback when dependency is unavailable
    mqtt = None


@dataclass
class MQTTVoteHandler:
    """Manage the MQTT client that listens for vote messages."""

    broker_host: str = MQTT_BROKER_HOST
    broker_port: int = MQTT_BROKER_PORT
    topic: str = MQTT_VOTE_TOPIC
    client_id: str = MQTT_CLIENT_ID
    keepalive: int = MQTT_KEEPALIVE_SECONDS

    def __post_init__(self) -> None:
        """Initialize the MQTT client if the dependency is available.

        Parameters:
            None.

        Returns:
            None.
        """
        self.client = None
        if mqtt is not None:
            self.client = mqtt.Client(client_id=self.client_id)
            self.client.on_connect = self._on_connect
            self.client.on_message = self._on_message

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: int) -> None:
        """Subscribe to the vote topic once the broker connection succeeds."""
        if rc == 0:
            logger.info("MQTT connected successfully")
            client.subscribe(self.topic)
        else:
            logger.error("MQTT connection failed with rc=%s", rc)

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        """Handle incoming MQTT payloads and process them locally."""
        try:
            payload = json.loads(message.payload.decode("utf-8"))
            result = process_vote(payload, ip_address="mqtt")
            logger.info("MQTT vote processed: %s", result.get("message"))
        except Exception:
            logger.exception("Failed to process MQTT message")

    def start(self) -> None:
        """Connect to the broker and begin listening for messages.

        Parameters:
            None.

        Returns:
            None.
        """
        if self.client is None:
            logger.warning("paho-mqtt is not available; MQTT listener disabled")
            return
        try:
            self.client.connect(self.broker_host, self.broker_port, self.keepalive)
            self.client.loop_start()
            logger.info("MQTT listener started on %s:%s", self.broker_host, self.broker_port)
        except Exception:
            logger.exception("Failed to start MQTT listener")

    def stop(self) -> None:
        """Stop the MQTT loop and disconnect from the broker.

        Parameters:
            None.

        Returns:
            None.
        """
        if self.client is None:
            return
        try:
            self.client.loop_stop()
            self.client.disconnect()
            logger.info("MQTT listener stopped")
        except Exception:
            logger.exception("Failed to stop MQTT listener")
