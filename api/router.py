from fastapi import APIRouter
from api.routes import health, scan

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(scan.router, prefix="/api/v1", tags=["scan"])
