from datetime import datetime

from bson import ObjectId
from fastapi import HTTPException

from app.core.constants import CASE_STATUSES
from app.db.mongodb import collection
from app.services.entity_service import extract_entities


def normalize_case_status(status: str) -> str:
    cleaned = (status or "new").strip().lower().replace(" ", "_")
    if cleaned not in CASE_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid case status")
    return cleaned


def fetch_related_reports(report_id: ObjectId, entities_flat: list[str], limit: int = 6) -> list[dict]:
    if not entities_flat:
        return []

    cursor = collection.find(
        {
            "_id": {"$ne": report_id},
            "entities_flat": {"$in": entities_flat},
        }
    ).sort("created_at", -1).limit(limit * 4)

    related_reports: list[dict] = []
    seen_ids: set[str] = set()
    for document in cursor:
        serialized = serialize_report(document, include_related=False)
        related_entities = document.get("entities_flat", [])
        shared = [value for value in related_entities if value in entities_flat][:5]
        serialized["shared_evidence"] = shared
        serialized["shared_evidence_count"] = len(shared)
        report_key = serialized["report_id"]
        if report_key not in seen_ids:
            seen_ids.add(report_key)
            related_reports.append(serialized)
        if len(related_reports) >= limit:
            break
    return related_reports


def serialize_report(document: dict, include_related: bool = True) -> dict:
    created_at = document.get("created_at")
    updated_at = document.get("updated_at")
    report_id = document.get("_id")
    entities = document.get("entity_summary", {})
    entities_flat = document.get("entities_flat", [])
    serialized = {
        "report_id": str(report_id),
        "title": document.get("title", ""),
        "url": document.get("url", ""),
        "location": document.get("location", ""),
        "lat": document.get("lat"),
        "lng": document.get("lng"),
        "type": document.get("type", "other"),
        "risk_score": document.get("risk_score"),
        "risk_level": document.get("risk_level"),
        "ai_confidence": document.get("ai_confidence"),
        "model_used": document.get("model_used"),
        "ai_explanation": document.get("ai_explanation"),
        "created_by": document.get("created_by", ""),
        "status": document.get("status", "new"),
        "analyst_notes": document.get("analyst_notes", ""),
        "updated_at": updated_at.isoformat() if isinstance(updated_at, datetime) else updated_at,
        "entity_summary": entities,
        "entities_flat": entities_flat,
    }
    if isinstance(created_at, datetime):
        serialized["created_at"] = created_at.isoformat()
    else:
        serialized["created_at"] = created_at
    if include_related and isinstance(report_id, ObjectId):
        serialized["related_reports"] = fetch_related_reports(report_id, entities_flat)
    return serialized
