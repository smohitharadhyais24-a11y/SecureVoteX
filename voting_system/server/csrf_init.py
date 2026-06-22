"""Shared CSRFProtect instance to avoid circular imports."""
from __future__ import annotations
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
