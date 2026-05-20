from fastapi import APIRouter, Depends, Query

from app.core.security import get_current_user
from app.services.geo_service import geo_suggestions_for_coords

router = APIRouter(prefix="/geo", tags=["geo"])


@router.get("/suggestions")
def geo_suggestions(
    lat: float = Query(..., ge=-90, le=90, description="WGS84 latitude"),
    lon: float = Query(..., ge=-180, le=180, description="WGS84 longitude"),
    current_user=Depends(get_current_user),
):
    return geo_suggestions_for_coords(lat, lon)
