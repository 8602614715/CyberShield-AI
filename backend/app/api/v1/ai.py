from fastapi import APIRouter, Depends

from app.core.security import get_current_user
from app.ml.analysis import build_ai_analysis, build_url_analysis
from app.schemas.reports import Report, UrlReport
from app.services.entity_service import extract_entities
from app.services.geo_service import extract_location, normalize_location

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/analyze")
def ai_analyze(report: Report, current_user=Depends(get_current_user)):
    location = (
        normalize_location(report.location)
        if report.location
        else extract_location(report.title)
    )
    analysis = build_ai_analysis(report.title, report.url)
    entities = extract_entities(report.title, report.url, report.analyst_notes)

    return {
        "title": report.title,
        "url": report.url,
        "location": location,
        "analysis": analysis,
        "entities": entities["entity_summary"],
        "requested_by": current_user["email"],
    }


@router.post("/analyze-url")
def ai_analyze_url(report: UrlReport, current_user=Depends(get_current_user)):
    analysis = build_url_analysis(report.url, report.context)
    entities = extract_entities(report.context, report.url, "")

    return {
        "url": report.url,
        "context": report.context,
        "analysis": analysis,
        "entities": entities["entity_summary"],
        "requested_by": current_user["email"],
    }
