from fastapi import APIRouter
from api.v1.endpoints import health, scan, blocklist, history

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(scan.router, prefix="/api/v1", tags=["scan"])
api_router.include_router(
    blocklist.router, prefix="/api/v1/blocklist", tags=["blocklist"]
)
api_router.include_router(history.router, prefix="/api/v1/history", tags=["history"])
