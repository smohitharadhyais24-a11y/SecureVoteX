"""One-click setup script for the IoT secure smart voting system."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from database.seed_data import seed_demo_voters
from server.database import initialize_database
from config.config import DATABASE_PATH, LOGS_DIR, REQUIREMENTS_PATH, SCHEMA_PATH


def ensure_python_version() -> None:
    """Check that the active interpreter is Python 3.8 or newer.

    Parameters:
        None.

    Returns:
        None.
    """
    if sys.version_info < (3, 8):
        raise RuntimeError("Python 3.8 or above is required")


def install_requirements() -> None:
    """Install all Python dependencies from the requirements file.

    Parameters:
        None.

    Returns:
        None.
    """
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_PATH)])


def create_database() -> None:
    """Create the database schema and seed the demo voters.

    Parameters:
        None.

    Returns:
        None.
    """
    initialize_database(DATABASE_PATH, SCHEMA_PATH)
    seed_demo_voters(DATABASE_PATH)


def create_log_directory() -> None:
    """Ensure the logs directory exists.

    Parameters:
        None.

    Returns:
        None.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    """Run the setup workflow in the required order.

    Parameters:
        None.

    Returns:
        None.
    """
    print("Setting up IoT Voting System...")
    ensure_python_version()
    install_requirements()
    create_database()
    create_log_directory()
    print(
        "Setup complete! Run these commands:\n"
        " 1. Start MQTT broker: mosquitto\n"
        " 2. Start server:      python server/app.py\n"
        " 3. Start simulator:   python booth/simulator.py"
    )


if __name__ == "__main__":
    main()
