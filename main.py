import logging
from fastapi import FastAPI
from core.config import settings
from api.v1.router import api_router
from core.exceptions import global_exception_handler
from core.http_client import start_client, stop_client
from contextlib import asynccontextmanager
import models.db_models  # noqa: F401 (Import to register models with SQLModel)

# Configure basic logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
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

# Exception handlers
app.add_exception_handler(Exception, global_exception_handler)


# Include API router
app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
