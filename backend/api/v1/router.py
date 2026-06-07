from fastapi import APIRouter, Depends
from api.v1.endpoints import health, scan, blocklist, history
from api.dependencies import verify_api_key

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(
    scan.router, prefix="/api/v1", tags=["scan"], dependencies=[Depends(verify_api_key)]
)
api_router.include_router(
    blocklist.router,
    prefix="/api/v1/blocklist",
    tags=["blocklist"],
    dependencies=[Depends(verify_api_key)],
)
api_router.include_router(
    history.router,
    prefix="/api/v1/history",
    tags=["history"],
    dependencies=[Depends(verify_api_key)],
)
