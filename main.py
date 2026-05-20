"""
Legacy entrypoint for local development.

Preferred:
  cd backend
  uvicorn app.main:app --reload
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from app.main import app  # noqa: E402

__all__ = ["app"]
