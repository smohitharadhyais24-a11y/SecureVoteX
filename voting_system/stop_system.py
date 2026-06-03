"""Graceful shutdown helper for local system processes."""
from __future__ import annotations

import subprocess


def main() -> None:
    """Stop known local service processes used by the project."""
    commands = [
        ["taskkill", "/IM", "mosquitto.exe", "/F"],
        ["taskkill", "/IM", "python.exe", "/F"],
    ]
    for cmd in commands:
        subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
