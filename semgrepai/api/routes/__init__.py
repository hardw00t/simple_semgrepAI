"""API routes."""

from fastapi import APIRouter

from .scans import router as scans_router
from .findings import router as findings_router
from .stats import router as stats_router
from .websocket import router as websocket_router

api_router = APIRouter()

api_router.include_router(scans_router, prefix="/scans", tags=["scans"])
api_router.include_router(findings_router, tags=["findings"])
api_router.include_router(stats_router, prefix="/stats", tags=["stats"])
api_router.include_router(websocket_router, tags=["websocket"])

__all__ = ["api_router"]
