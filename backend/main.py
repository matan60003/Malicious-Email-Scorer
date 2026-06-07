from fastapi import FastAPI
from core.config import settings
from api.v1.router import api_router
from core.exceptions import global_exception_handler
from core.http_client import start_client, stop_client
from contextlib import asynccontextmanager
from core.database import create_db_and_tables
import orm.db_models  # noqa: F401 (Import to register models with SQLModel)

import uuid
import structlog
from fastapi import Request
from core.logging import setup_logging

# Configure structured JSON logging
setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    # Start global HTTP client
    await start_client()
    yield
    # Stop global HTTP client
    await stop_client()


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)


@app.middleware("http")
async def structured_logging_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    # Clear contextvars for the new request
    structlog.contextvars.clear_contextvars()
    # Bind request context so every log line contains these fields
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )

    logger = structlog.get_logger(__name__)
    logger.info("Request started")

    try:
        response = await call_next(request)
        structlog.contextvars.bind_contextvars(status_code=response.status_code)
        logger.info("Request finished")
        return response
    except Exception as e:
        structlog.contextvars.bind_contextvars(status_code=500)
        logger.exception("Request failed")
        raise e


# Exception handlers
app.add_exception_handler(Exception, global_exception_handler)


# Include API router
app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
