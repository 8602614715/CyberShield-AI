from fastapi import APIRouter

from app.api.v1 import ai, analytics, auth, geo, health, models, reports

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(geo.router)
api_router.include_router(ai.router)
api_router.include_router(models.router)
api_router.include_router(reports.router)
api_router.include_router(analytics.router)
