from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_email_safe():
    payload = {
        "id": "email_123",
        "sender": {"email": "test@example.com", "domain": "example.com"},
        "subject": "Hello there",
        "body_text": "Just saying hi.",
        "urls": [],
        "headers": {"spf_status": "PASS"},
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "email_123"
    assert data["verdict"] == "SAFE"
    assert data["score"] == 0


def test_scan_email_suspicious():
    payload = {
        "id": "email_124",
        "sender": {"email": "hacker@bad.com", "domain": "bad.com"},
        "subject": "URGENT password reset",
        "body_text": "Click here.",
        "urls": ["http://bad.com/reset"],
        "headers": {"spf_status": "FAIL"},
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "MALICIOUS"  # 30 + 40 = 70
    assert data["score"] == 70
