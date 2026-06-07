from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from sqlmodel import Session
from core.database import engine
from core.config import settings

api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != settings.API_KEY_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key

def get_session():
    with Session(engine) as session:
        yield session
