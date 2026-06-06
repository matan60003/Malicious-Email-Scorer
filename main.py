import logging
from fastapi import FastAPI
from core.config import settings
from api.router import api_router
from core.exceptions import global_exception_handler
from core.database import create_db_and_tables
import models.db_models  # Import to register models with SQLModel

# Configure basic logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

app = FastAPI(
    title=settings.PROJECT_NAME, openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Exception handlers
app.add_exception_handler(Exception, global_exception_handler)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# Include API router
app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
