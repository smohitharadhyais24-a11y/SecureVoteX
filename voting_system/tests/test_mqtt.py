"""MQTT handler tests with mocked client behavior."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from server.mqtt_handler import MQTTVoteHandler


class DummyClient:
    def __init__(self, *args, **kwargs):
        self.published = []
        self.subscriptions = []
        self.connected = False
        self.on_connect = None
        self.on_disconnect = None
        self.on_message = None

    def reconnect_delay_set(self, min_delay: int, max_delay: int) -> None:
        return None

    def subscribe(self, topic: str, qos: int = 0):
        self.subscriptions.append((topic, qos))
        return (0, 1)

    def connect(self, host: str, port: int, keepalive: int):
        self.connected = True
        return 0

    def loop_start(self):
        return None

    def loop_stop(self):
        return None

    def disconnect(self):
        self.connected = False
        return None

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False):
        self.published.append((topic, payload, qos, retain))
        return None


class DummyMQTTModule:
    Client = DummyClient


class TestMQTTHandler(unittest.TestCase):
    """Verify MQTT start/stop and publish logic."""

    @patch("server.mqtt_handler.mqtt", new=DummyMQTTModule())
    def test_publish_response_writes_to_client(self) -> None:
        handler = MQTTVoteHandler()
        handler.start_mqtt_client()
        handler.publish_response("voting/test", {"ok": True})
        self.assertTrue(len(handler.client.published) > 0)
        handler.stop_mqtt_client()

    @patch("server.mqtt_handler.mqtt", new=DummyMQTTModule())
    def test_connect_subscribes_topics(self) -> None:
        handler = MQTTVoteHandler()
        handler._on_connect(handler.client, None, None, 0)
        topics = [topic for topic, _qos in handler.client.subscriptions]
        self.assertIn("voting/auth/request", topics)
        self.assertIn("voting/vote/submit", topics)


if __name__ == "__main__":
    unittest.main()
