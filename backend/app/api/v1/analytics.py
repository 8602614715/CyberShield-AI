from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from app.core.security import get_current_user
from app.db.mongodb import collection

router = APIRouter(tags=["analytics"])


@router.get("/stats/type")
def stats_by_type(current_user=Depends(get_current_user)):
    pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
    return list(collection.aggregate(pipeline))


@router.get("/alerts")
def alerts(current_user=Depends(get_current_user)):
    pipeline = [
        {"$group": {"_id": "$location", "count": {"$sum": 1}}},
        {"$match": {"count": {"$gte": 3}}},
    ]
    return list(collection.aggregate(pipeline))


@router.get("/api/predict/risk_trend")
def predict_risk_trend(current_user=Depends(get_current_user)):
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)

    pipeline = [
        {
            "$match": {
                "created_at": {"$gte": seven_days_ago},
                "risk_level": {"$in": ["critical", "high"]},
            }
        },
        {"$group": {"_id": "$location", "recent_count": {"$sum": 1}}},
        {"$sort": {"recent_count": -1}},
        {"$limit": 5},
    ]
    hotspots = list(collection.aggregate(pipeline))

    predictions = []
    for hotspot in hotspots:
        loc = hotspot["_id"]
        count = hotspot["recent_count"]
        predicted_increase = count * 1.5
        predictions.append(
            {
                "location": loc,
                "recent_incidents": count,
                "predicted_next_week": round(predicted_increase, 1),
                "trend": "upward" if count > 2 else "stable",
            }
        )

    return {
        "status": "success",
        "predicted_hotspots": predictions,
        "message": (
            "Predictions for locations at risk of increased fraudulent activities "
            "based on recent high/critical reports."
        ),
    }
