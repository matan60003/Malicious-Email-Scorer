import pytest
from sqlmodel import SQLModel, Session, create_engine
from fastapi.testclient import TestClient
from main import app
from api.dependencies import get_session
from models.db_models import Blocklist
from sqlalchemy.pool import StaticPool

# Use in-memory SQLite for testing
sqlite_url = "sqlite://"
engine = create_engine(
    sqlite_url, connect_args={"check_same_thread": False}, poolclass=StaticPool
)


def get_session_override():
    with Session(engine) as session:
        yield session


app.dependency_overrides[get_session] = get_session_override


@pytest.fixture(name="session", autouse=True)
def session_fixture():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    SQLModel.metadata.drop_all(engine)


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_add_to_blocklist(client: TestClient):
    response = client.post(
        "/api/v1/blocklist/", json={"value": "test@evil.com", "type": "email"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["value"] == "test@evil.com"


def test_scan_with_blocklist(client: TestClient, session: Session):
    # Add to blocklist
    blocked_user = Blocklist(value="blocked@hacker.com", type="email")
    session.add(blocked_user)
    session.commit()

    # Scan email from blocked user
    payload = {
        "id": "msg-123",
        "sender": {"email": "blocked@hacker.com", "domain": "hacker.com"},
        "subject": "Hello",
        "body_text": "This is a test.",
        "urls": [],
        "headers": {"spf_status": "PASS", "dkim_status": "PASS"},
    }

    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "MALICIOUS"
    assert data["score"] == 100
    assert "Sender is on your personal blocklist." in data["reasons"]
