"""MQTT server-side communication layer for auth, voting, and health topics."""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from config.config import (
    HEALTH_OFFLINE_TIMEOUT_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
    MQTT_ADMIN_EVENTS_TOPIC,
    MQTT_AUTH_REQUEST_TOPIC,
    MQTT_AUTH_RESPONSE_TOPIC,
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_KEEPALIVE_SECONDS,
    MQTT_QOS,
    MQTT_SERVER_CLIENT_ID,
    MQTT_USE_TLS,
    MQTT_VOTE_RESPONSE_TOPIC,
    MQTT_VOTE_SUBMIT_TOPIC,
)
from security.tls_config import load_tls_configuration
from server.database import get_voter_by_rfid, update_component_status
from server.socketio_handler import emit_system_health_update
from server.vote_verifier import process_vote

logger = logging.getLogger(__name__)

try:  # pragma: no cover - dependency may be absent during static checks
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover - fallback when dependency is unavailable
    mqtt = None


@dataclass
class MQTTVoteHandler:
    """Handle MQTT auth/vote/health requests and publish responses."""

    broker_host: str = MQTT_BROKER_HOST
    broker_port: int = MQTT_BROKER_PORT
    keepalive: int = MQTT_KEEPALIVE_SECONDS
    client_id: str = MQTT_SERVER_CLIENT_ID
    use_tls: bool = MQTT_USE_TLS
    _last_health_seen: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.client = None
        self._monitor_stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._message_timestamps: list[float] = []
        if mqtt is None:
            return
        self.client = mqtt.Client(client_id=self.client_id)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: int) -> None:
        if rc != 0:
            logger.error("MQTT connection failed with rc=%s", rc)
            return
        logger.info("MQTT connected to broker at %s:%s", self.broker_host, self.broker_port)
        client.subscribe(MQTT_AUTH_REQUEST_TOPIC, qos=MQTT_QOS)
        client.subscribe(MQTT_VOTE_SUBMIT_TOPIC, qos=MQTT_QOS)
        client.subscribe("voting/system/health", qos=MQTT_QOS)
        client.subscribe("voting/booth/heartbeat", qos=MQTT_QOS)

    def _on_disconnect(self, client: Any, userdata: Any, rc: int) -> None:
        logger.warning("MQTT disconnected (rc=%s). Auto-reconnect will be attempted.", rc)

    def get_mqtt_message_rate(self) -> float:
        """Calculate the average incoming messages per second over a 10s window."""
        now = time.time()
        self._message_timestamps = [t for t in self._message_timestamps if now - t <= 10]
        return round(len(self._message_timestamps) / 10.0, 2)

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        self._message_timestamps.append(time.time())
        topic = str(message.topic)
        try:
            payload = json.loads(message.payload.decode("utf-8"))
        except Exception:
            logger.exception("Invalid MQTT JSON payload on topic %s", topic)
            return

        if topic == MQTT_AUTH_REQUEST_TOPIC:
            self._handle_auth_request(payload)
            return
        if topic == MQTT_VOTE_SUBMIT_TOPIC:
            self._handle_vote_submit(payload)
            return
        if topic == "voting/system/health":
            self._handle_health(payload)
            return
        if topic == "voting/booth/heartbeat":
            self._handle_booth_heartbeat(payload)
            return

    def _handle_auth_request(self, payload: dict[str, Any]) -> None:
        request_id = str(payload.get("request_id", ""))
        booth_id = str(payload.get("booth_id", ""))
        rfid = str(payload.get("rfid", ""))
        fingerprint_id = payload.get("fingerprint_id")

        voter = get_voter_by_rfid(rfid)
        if voter is None:
            response = {
                "request_id": request_id,
                "booth_id": booth_id,
                "registered": False,
                "verified": False,
                "message": "RFID not registered",
            }
            self.publish_response(MQTT_AUTH_RESPONSE_TOPIC, response)
            return

        verified = True
        if fingerprint_id is not None:
            verified = int(voter["fingerprint_id"]) == int(fingerprint_id)

        response = {
            "request_id": request_id,
            "booth_id": booth_id,
            "registered": True,
            "verified": verified,
            "has_voted": bool(voter["has_voted"]),
            "name": voter["name"],
            "fingerprint_id": voter["fingerprint_id"],
            "message": "Authentication success" if verified else "Fingerprint mismatch",
        }
        self.publish_response(MQTT_AUTH_RESPONSE_TOPIC, response)

    def _handle_vote_submit(self, payload: dict[str, Any]) -> None:
        request_id = str(payload.get("request_id", ""))
        vote_payload = payload.get("vote_payload") if isinstance(payload.get("vote_payload"), dict) else payload
        result = process_vote(vote_payload, ip_address="mqtt")
        response = {
            "request_id": request_id,
            "booth_id": vote_payload.get("booth_id"),
            "status": result.get("status"),
            "event_type": result.get("event_type"),
            "message": result.get("message"),
            "vote_id": result.get("vote_id"),
        }
        self.publish_response(MQTT_VOTE_RESPONSE_TOPIC, response)
        self.publish_response(MQTT_ADMIN_EVENTS_TOPIC, {"type": "vote_event", "payload": response})

    def _handle_health(self, payload: dict[str, Any]) -> None:
        component = str(payload.get("component", "unknown"))
        status = str(payload.get("status", "UNKNOWN"))
        key = f"{component}"
        self._last_health_seen[key] = time.time()
        update_component_status(component=component, status=status, message="heartbeat over mqtt")
        emit_system_health_update({"component": component, "status": status})

    def _handle_booth_heartbeat(self, payload: dict[str, Any]) -> None:
        booth_id = str(payload.get("booth_id", "unknown"))
        wifi_status = str(payload.get("wifi_status", "DISCONNECTED"))
        mqtt_status = str(payload.get("mqtt_status", "DISCONNECTED"))
        buffered = payload.get("buffered_votes", 0)
        free_heap = payload.get("free_heap", 0)
        version = str(payload.get("firmware_version", "v1.0.0"))

        status = "ONLINE" if (wifi_status == "CONNECTED" and mqtt_status == "CONNECTED") else "OFFLINE"
        msg = f"FW: {version} | Heap: {free_heap} B | Buffered: {buffered}"

        component = f"booth:{booth_id}"
        self._last_health_seen[component] = time.time()
        update_component_status(component=component, status=status, message=msg)
        
        # Prepare rich health update event
        health_payload = {
            "component": component,
            "status": status,
            "wifi_status": wifi_status,
            "mqtt_status": mqtt_status,
            "buffered_votes": buffered,
            "free_heap": free_heap,
            "firmware_version": version,
            "fsm_state": payload.get("fsm_state", "UNKNOWN"),
            "current_voter": payload.get("current_voter", ""),
            "rfid_status": payload.get("rfid_status", ""),
            "fingerprint_status": payload.get("fingerprint_status", ""),
            "lcd_status": payload.get("lcd_status", "")
        }
        emit_system_health_update(health_payload)

    def _health_monitor_loop(self) -> None:
        timeout = float(HEALTH_OFFLINE_TIMEOUT_SECONDS)
        while not self._monitor_stop.wait(HEARTBEAT_INTERVAL_SECONDS):
            now = time.time()
            for component, seen_at in list(self._last_health_seen.items()):
                if now - seen_at > timeout:
                    update_component_status(component=component, status="OFFLINE", message="No heartbeat within timeout")
                    emit_system_health_update({"component": component, "status": "OFFLINE"})

    def start_mqtt_client(self) -> None:
        if self.client is None:
            logger.warning("paho-mqtt is unavailable; MQTT listener disabled")
            return
        try:
            if self.use_tls:
                tls_config = load_tls_configuration()
                self.client.tls_set(
                    ca_certs=tls_config["ca_certificate"],
                    certfile=tls_config["client_certificate"],
                    keyfile=tls_config["client_key"],
                )
            self.client.connect(self.broker_host, self.broker_port, self.keepalive)
            self.client.loop_start()
            self._monitor_stop.clear()
            self._monitor_thread = threading.Thread(target=self._health_monitor_loop, daemon=True)
            self._monitor_thread.start()
            logger.info("MQTT handler started")
        except Exception:
            logger.exception("Failed to start MQTT client")

    def stop_mqtt_client(self) -> None:
        if self.client is None:
            return
        try:
            self._monitor_stop.set()
            if self._monitor_thread is not None:
                self._monitor_thread.join(timeout=2)
            self.client.loop_stop()
            self.client.disconnect()
            logger.info("MQTT handler stopped")
        except Exception:
            logger.exception("Failed to stop MQTT client")

    def publish_response(self, topic: str, payload: dict[str, Any]) -> None:
        if self.client is None:
            return
        try:
            self.client.publish(topic, json.dumps(payload), qos=MQTT_QOS, retain=False)
        except Exception:
            logger.exception("Failed publishing MQTT response to %s", topic)

    def publish_health_status(self, component: str, status: str) -> None:
        self.publish_response(
            "voting/system/health",
            {
                "component": component,
                "status": status,
                "source": "server",
            },
        )

    # Backward-compatible wrappers
    def start(self) -> None:
        self.start_mqtt_client()

    def stop(self) -> None:
        self.stop_mqtt_client()
