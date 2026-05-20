from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pymongo import ReturnDocument

from app.core.security import get_current_user
from app.db.mongodb import collection
from app.ml.analysis import build_ai_analysis
from app.schemas.reports import Report, ReportUpdate
from app.services.alert_service import send_alert_notification
from app.services.entity_service import extract_entities
from app.services.geo_service import extract_location, get_coordinates, normalize_location
from app.services.report_service import (
    fetch_related_reports,
    normalize_case_status,
    serialize_report,
)

router = APIRouter(tags=["reports"])


@router.post("/report")
def add_report(
    report: Report,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
):
    title = report.title
    status = normalize_case_status(report.status)
    analyst_notes = report.analyst_notes.strip()
    entity_bundle = extract_entities(title, report.url, analyst_notes)

    location = normalize_location(report.location)
    if location == "" or location == "unknown":
        location = extract_location(title)

    lat, lng = get_coordinates(location)
    analysis = build_ai_analysis(title, report.url)

    data = {
        "title": title,
        "url": report.url,
        "location": location,
        "lat": lat,
        "lng": lng,
        "type": analysis["predicted_type"],
        "ai_confidence": analysis["confidence"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "model_used": analysis["model_used"],
        "ai_explanation": analysis["explanation"],
        "created_at": datetime.now(timezone.utc),
        "created_by": current_user["email"],
        "status": status,
        "analyst_notes": analyst_notes,
        "entity_summary": entity_bundle["entity_summary"],
        "entities_flat": entity_bundle["entities_flat"],
    }

    inserted = collection.insert_one(data)

    if analysis["risk_level"] == "critical":
        background_tasks.add_task(
            send_alert_notification,
            str(inserted.inserted_id),
            "critical",
            (
                f"Type: {analysis['predicted_type']} - Confidence: {analysis['confidence']} "
                f"- Location: {location}"
            ),
        )

    return {
        "report_id": str(inserted.inserted_id),
        "message": "Report added",
        "type": analysis["predicted_type"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "confidence": analysis["confidence"],
        "location": location,
        "lat": lat,
        "lng": lng,
        "status": status,
        "analyst_notes": analyst_notes,
        "entities": entity_bundle["entity_summary"],
    }


@router.get("/reports")
def get_reports(current_user=Depends(get_current_user)):
    documents = collection.find({}).sort("created_at", -1)
    return [serialize_report(document) for document in documents]


@router.patch("/reports/{report_id}")
def update_report(
    report_id: str,
    update: ReportUpdate,
    current_user=Depends(get_current_user),
):
    status = normalize_case_status(update.status)
    analyst_notes = update.analyst_notes.strip()

    if current_user.get("role", "viewer") not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Only analysts or admins can update cases")

    try:
        object_id = ObjectId(report_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid report id") from exc

    existing_report = collection.find_one({"_id": object_id})
    if not existing_report:
        raise HTTPException(status_code=404, detail="Report not found")

    entity_bundle = extract_entities(
        existing_report.get("title", ""),
        existing_report.get("url", ""),
        analyst_notes,
    )

    result = collection.find_one_and_update(
        {"_id": object_id},
        {
            "$set": {
                "status": status,
                "analyst_notes": analyst_notes,
                "entity_summary": entity_bundle["entity_summary"],
                "entities_flat": entity_bundle["entities_flat"],
                "updated_at": datetime.now(timezone.utc),
                "updated_by": current_user["email"],
            }
        },
        return_document=ReturnDocument.AFTER,
    )

    return serialize_report(result)


@router.get("/reports/{report_id}/links")
def report_links(report_id: str, current_user=Depends(get_current_user)):
    try:
        object_id = ObjectId(report_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid report id") from exc

    document = collection.find_one({"_id": object_id})
    if not document:
        raise HTTPException(status_code=404, detail="Report not found")

    entities_flat = document.get("entities_flat", [])
    related_reports = fetch_related_reports(object_id, entities_flat, limit=10)
    return {
        "report_id": report_id,
        "entity_summary": document.get("entity_summary", {}),
        "related_reports": related_reports,
    }


@router.get("/reports/map")
def map_reports(current_user=Depends(get_current_user)):
    return list(
        collection.find(
            {},
            {
                "_id": 0,
                "title": 1,
                "location": 1,
                "lat": 1,
                "lng": 1,
                "type": 1,
                "risk_score": 1,
                "risk_level": 1,
            },
        )
    )


@router.get("/reports/location/{loc}")
def reports_by_location(loc: str, current_user=Depends(get_current_user)):
    return list(
        collection.find(
            {"location": normalize_location(loc)},
            {"_id": 0},
        )
    )
