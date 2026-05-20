from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from app.config import MODEL_DIR
from app.db.mongodb import client

router = APIRouter(tags=["health"])


@router.get("/")
def home():
    return {"message": "Cybercrime Intelligence API Running"}


@router.get("/health")
def health():
    try:
        client.admin.command("ping")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="MongoDB unreachable") from exc
    return {
        "status": "ok",
        "mongodb": True,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "models_dir_exists": MODEL_DIR.is_dir(),
    }
