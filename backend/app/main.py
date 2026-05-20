from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.config import CORS_ORIGINS
from app.db.indexes import ensure_indexes


@asynccontextmanager
async def lifespan(application: FastAPI):
    ensure_indexes()
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="CyberShield AI API",
        description="Cyber fraud reporting and intelligence API",
        version="1.0.0",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(api_router)
    return application


app = create_app()
