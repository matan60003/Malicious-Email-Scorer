from fastapi.testclient import TestClient
from main import app
from unittest.mock import patch, AsyncMock
from sqlmodel import SQLModel, Session, create_engine
from core.database import get_session
from sqlalchemy.pool import StaticPool
import pytest

# Use in-memory SQLite for testing
sqlite_url = "sqlite://"
engine = create_engine(
    sqlite_url, 
    connect_args={"check_same_thread": False}, 
    poolclass=StaticPool
)

@pytest.fixture(name="client")
def client_fixture():
    SQLModel.metadata.create_all(engine)
    
    def get_session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = get_session_override
    with TestClient(app) as client:
        yield client
    
    app.dependency_overrides.clear()
    SQLModel.metadata.drop_all(engine)


def test_health_check(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@patch("services.analyzer.gather_intel", new_callable=AsyncMock)
def test_scan_email_safe(mock_gather, client: TestClient):
    mock_gather.return_value = {"virustotal": {}, "safebrowsing": {}}

    payload = {
        "id": "email_123",
        "sender": {"email": "test@example.com", "domain": "example.com"},
        "subject": "Hello there",
        "body_text": "Just saying hi.",
        "urls": [],
        "headers": {"spf_status": "PASS", "dkim_status": "PASS"},
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "email_123"
    assert data["verdict"] == "SAFE"
    assert data["score"] == 0


@patch("services.analyzer.gather_intel", new_callable=AsyncMock)
def test_scan_email_suspicious(mock_gather, client: TestClient):
    mock_gather.return_value = {"virustotal": {}, "safebrowsing": {}}

    payload = {
        "id": "email_124",
        "sender": {"email": "hacker@bad.com", "domain": "bad.com"},
        "subject": "URGENT password reset",
        "body_text": "Click here.",
        "urls": ["http://bad.com/reset"],
        "headers": {"spf_status": "FAIL", "dkim_status": "PASS"},
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Score should be:
    # URGENT password -> +15
    # SPF FAIL -> +20
    # Total = 35 -> SUSPICIOUS
    assert data["verdict"] == "SUSPICIOUS"
    assert data["score"] == 35
