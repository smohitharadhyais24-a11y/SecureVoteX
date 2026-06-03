"""MQTT booth-side client for auth, vote submit, and heartbeat flows."""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any
from uuid import uuid4

from config.config import (
    BOOTH_ID,
    HEARTBEAT_INTERVAL_SECONDS,
    MQTT_AUTH_REQUEST_TOPIC,
    MQTT_AUTH_RESPONSE_TOPIC,
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_CLIENT_ID,
    MQTT_HEALTH_TOPIC,
    MQTT_KEEPALIVE_SECONDS,
    MQTT_QOS,
    MQTT_RESPONSE_TIMEOUT_SECONDS,
    MQTT_USE_TLS,
    MQTT_VOTE_RESPONSE_TOPIC,
    MQTT_VOTE_SUBMIT_TOPIC,
)
from security.tls_config import load_tls_configuration

logger = logging.getLogger(__name__)

try:  # pragma: no cover
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover
    mqtt = None


class BoothMqttClient:
    """A small request-response wrapper around paho-mqtt for booth operations."""

    def __init__(self, booth_id: str = BOOTH_ID) -> None:
        self.booth_id = booth_id
        self._responses: dict[str, dict[str, Any]] = {}
        self._responses_lock = threading.Lock()
        self._response_event = threading.Event()
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self.client = None

        if mqtt is None:
            return

        self.client = mqtt.Client(client_id=f"{MQTT_CLIENT_ID}_{booth_id}")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: int) -> None:
        if rc != 0:
            logger.error("Booth MQTT connect failed rc=%s", rc)
            return
        client.subscribe(MQTT_AUTH_RESPONSE_TOPIC, qos=MQTT_QOS)
        client.subscribe(MQTT_VOTE_RESPONSE_TOPIC, qos=MQTT_QOS)

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        try:
            payload = json.loads(message.payload.decode("utf-8"))
            request_id = str(payload.get("request_id", ""))
            if not request_id:
                return
            with self._responses_lock:
                self._responses[request_id] = payload
            self._response_event.set()
        except Exception:
            logger.exception("Invalid booth MQTT response payload")

    def connect(self) -> bool:
        if self.client is None:
            return False
        try:
            if MQTT_USE_TLS:
                tls_config = load_tls_configuration()
                self.client.tls_set(
                    ca_certs=tls_config["ca_certificate"],
                    certfile=tls_config["client_certificate"],
                    keyfile=tls_config["client_key"],
                )
            self.client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, MQTT_KEEPALIVE_SECONDS)
            self.client.loop_start()
            return True
        except Exception:
            logger.exception("Failed to connect booth MQTT client")
            return False

    def disconnect(self) -> None:
        if self.client is None:
            return
        try:
            self.stop_heartbeat()
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            logger.exception("Failed to disconnect booth MQTT client")

    def _publish_and_wait(self, topic: str, payload: dict[str, Any], timeout: int = MQTT_RESPONSE_TIMEOUT_SECONDS) -> dict[str, Any]:
        if self.client is None:
            return {"error": "mqtt_unavailable"}
        request_id = str(uuid4())
        outbound = dict(payload)
        outbound["request_id"] = request_id
        outbound["booth_id"] = self.booth_id

        with self._responses_lock:
            self._responses.pop(request_id, None)
        self._response_event.clear()

        self.client.publish(topic, json.dumps(outbound), qos=MQTT_QOS, retain=False)

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._response_event.wait(timeout=0.2):
                self._response_event.clear()
            with self._responses_lock:
                response = self._responses.pop(request_id, None)
            if response is not None:
                return response
        return {"request_id": request_id, "error": "timeout"}

    def authenticate_rfid(self, rfid: str) -> dict[str, Any]:
        return self._publish_and_wait(MQTT_AUTH_REQUEST_TOPIC, {"rfid": rfid})

    def authenticate_fingerprint(self, rfid: str, fingerprint_id: int) -> dict[str, Any]:
        return self._publish_and_wait(MQTT_AUTH_REQUEST_TOPIC, {"rfid": rfid, "fingerprint_id": fingerprint_id})

    def submit_vote(self, vote_payload: dict[str, Any]) -> dict[str, Any]:
        return self._publish_and_wait(MQTT_VOTE_SUBMIT_TOPIC, {"vote_payload": vote_payload})

    def publish_heartbeat(self, status: str = "ONLINE") -> None:
        if self.client is None:
            return
        payload = {"component": f"booth:{self.booth_id}", "status": status}
        self.client.publish(MQTT_HEALTH_TOPIC, json.dumps(payload), qos=MQTT_QOS, retain=False)

    def start_heartbeat(self) -> None:
        if self.client is None or (self._heartbeat_thread and self._heartbeat_thread.is_alive()):
            return

        def _loop() -> None:
            while not self._heartbeat_stop.wait(HEARTBEAT_INTERVAL_SECONDS):
                self.publish_heartbeat("ONLINE")

        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(target=_loop, daemon=True)
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2)
