"""Central configuration for the IoT secure smart voting system.

This module keeps all important application settings in one place so the
backend, simulator, database setup, and tests can share the same values.
"""
from __future__ import annotations

from pathlib import Path

BASE_DIR: Path = Path(__file__).resolve().parent.parent
VOTING_SYSTEM_DIR: Path = BASE_DIR
BOOTH_DIR: Path = BASE_DIR / "booth"
SERVER_DIR: Path = BASE_DIR / "server"
DATABASE_DIR: Path = BASE_DIR / "database"
SECURITY_DIR: Path = BASE_DIR / "security"
DASHBOARD_DIR: Path = BASE_DIR / "dashboard"
LOGS_DIR: Path = BASE_DIR / "logs"
CERTIFICATES_DIR: Path = SECURITY_DIR / "certificates"
DATABASE_PATH: Path = DATABASE_DIR / "voting.db"
SCHEMA_PATH: Path = DATABASE_DIR / "schema.sql"
REQUIREMENTS_PATH: Path = BASE_DIR / "requirements.txt"
LOG_FILE_PATH: Path = LOGS_DIR / "voting.log"
OFFLINE_BUFFER_PATH: Path = BASE_DIR / "booth" / "buffered_votes.json"

MQTT_BROKER_HOST: str = "localhost"
MQTT_BROKER_PORT: int = 1883
MQTT_TLS_PORT: int = 8883
MQTT_KEEPALIVE_SECONDS: int = 60
MQTT_AUTH_REQUEST_TOPIC: str = "voting/auth/request"
MQTT_AUTH_RESPONSE_TOPIC: str = "voting/auth/response"
MQTT_VOTE_SUBMIT_TOPIC: str = "voting/vote/submit"
MQTT_VOTE_RESPONSE_TOPIC: str = "voting/vote/response"
MQTT_HEALTH_TOPIC: str = "voting/system/health"
MQTT_ADMIN_EVENTS_TOPIC: str = "voting/admin/events"
MQTT_RESPONSE_TIMEOUT_SECONDS: int = 5
MQTT_CLIENT_ID: str = "voting_system_booth"
MQTT_SERVER_CLIENT_ID: str = "voting_system_server"
MQTT_USE_TLS: bool = True
MQTT_ENABLED: bool = True
MQTT_QOS: int = 1
HEARTBEAT_INTERVAL_SECONDS: int = 30
HEALTH_OFFLINE_TIMEOUT_SECONDS: int = 90
NETWORK_MODE: str = "SIMULATION"

FLASK_HOST: str = "127.0.0.1"
FLASK_PORT: int = 5000
FLASK_DEBUG: bool = True

SHA256_SECRET_SALT: str = "COLLEGE_PROJECT_VOTING_SALT_CHANGE_ME"
SECRET_KEY: str = "iot_secure_voting_2026"

ELECTION_NAME: str = "IoT Secure Smart Voting System - College Election"
ELECTION_START_TIME: str = "2026-06-03T09:00:00"
ELECTION_END_TIME: str = "2026-06-03T17:00:00"
CANDIDATE_NAMES: dict[str, str] = {
    "A": "Candidate A",
    "B": "Candidate B",
    "C": "Candidate C",
}
VALID_CANDIDATES: tuple[str, ...] = tuple(CANDIDATE_NAMES.keys())
MAX_FINGERPRINT_ATTEMPTS: int = 3
VOTE_TIMEOUT_SECONDS: int = 30
BOOTH_ID: str = "booth01"
DEFAULT_SOURCE_IP: str = "127.0.0.1"

LOGGING_LEVEL: str = "INFO"
LOGGING_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
