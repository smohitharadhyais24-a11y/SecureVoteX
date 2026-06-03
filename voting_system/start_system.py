"""Startup script for Phase 2 networked voting system."""
from __future__ import annotations

import logging

from security.certificate_generator import generate_certificates
from security.tls_config import validate_certificates
from server.app import create_app
from server.database import initialize_database
from server.mqtt_handler import MQTTVoteHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    """Verify prerequisites and start MQTT + Flask + SocketIO services."""
    logger.info("1) Verifying TLS certificates")
    if not validate_certificates():
        logger.info("Certificates missing, generating now")
        generate_certificates()

    logger.info("2) Verifying database")
    initialize_database()

    logger.info("3) Creating Flask app")
    app = create_app()

    logger.info("4) Starting MQTT client")
    mqtt_handler = app.extensions.get("mqtt_handler")
    if isinstance(mqtt_handler, MQTTVoteHandler):
        mqtt_handler.start_mqtt_client()

    logger.info("5) Starting SocketIO/Flask server")
    socketio = app.extensions.get("socketio")
    logger.info("System ready: Flask + MQTT + SocketIO")
    try:
        if socketio is not None:
            socketio.run(app, host="127.0.0.1", port=5000, debug=False)
        else:
            app.run(host="127.0.0.1", port=5000, debug=False)
    finally:
        if isinstance(mqtt_handler, MQTTVoteHandler):
            mqtt_handler.stop_mqtt_client()


if __name__ == "__main__":
    main()
