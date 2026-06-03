"""Flask application entry point for the secure smart voting system."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask

from config.config import FLASK_DEBUG, FLASK_HOST, FLASK_PORT, LOG_FILE_PATH, LOGGING_FORMAT, LOGGING_LEVEL
from server.database import initialize_database
from server.mqtt_handler import MQTTVoteHandler
from server.routes import register_routes
from server.socketio_handler import init_socketio

logging.basicConfig(level=getattr(logging, LOGGING_LEVEL.upper(), logging.INFO), format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)


def configure_file_logging(app: Flask) -> None:
    """Attach rotating file logging to the Flask app.

    Parameters:
        app: The Flask application instance.

    Returns:
        None.
    """
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=1_000_000, backupCount=3)
    file_handler.setLevel(getattr(logging, LOGGING_LEVEL.upper(), logging.INFO))
    file_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    app.logger.addHandler(file_handler)


def create_app() -> Flask:
    """Create and configure the Flask application object.

    Parameters:
        None.

    Returns:
        A configured Flask app instance.
    """
    project_root = Path(__file__).resolve().parent.parent
    dashboard_dir = project_root / "dashboard"
    app = Flask(
        __name__,
        template_folder=str(dashboard_dir / "templates"),
        static_folder=str(dashboard_dir / "static"),
    )
    app.config["JSON_SORT_KEYS"] = False
    configure_file_logging(app)
    initialize_database()
    register_routes(app)
    app.extensions["mqtt_handler"] = MQTTVoteHandler()
    app.extensions["socketio"] = init_socketio(app)
    return app


app = create_app()


if __name__ == "__main__":
    mqtt_handler = app.extensions.get("mqtt_handler")
    socketio = app.extensions.get("socketio")
    try:
        if isinstance(mqtt_handler, MQTTVoteHandler):
            mqtt_handler.start_mqtt_client()
        if socketio is not None:
            socketio.run(app, host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
        else:
            app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
    finally:
        if isinstance(mqtt_handler, MQTTVoteHandler):
            mqtt_handler.stop_mqtt_client()
