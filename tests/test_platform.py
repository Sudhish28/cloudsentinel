from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.main import create_app, Event
from app.detection import Detector
from scripts.cloudtrail import normalize
import pytest
import os

KEY = "test-secret-at-least-16"

@pytest.fixture
def client(tmp_path):
    app = create_app(os.getenv("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}", KEY)
    # PostgreSQL CI uses one clean database per job; unique IDs isolate cases.
    with TestClient(app) as c:
        yield c

def event(**kwargs):
    data = dict(event_id="one", timestamp="2026-01-01T12:00:00Z", principal="alice", action="GetObject")
    return dict(data, **kwargs)

def test_auth(client):
    assert client.get("/api/alerts").status_code == 401
    assert client.post("/api/events", json={"events":[event()]}).status_code == 401

def test_ingest_idempotency_summary(client):
    headers = {"X-API-Key": KEY}
    body = {"events": [event(event_id="iam-test", action="AttachUserPolicy")]}
    assert client.post("/api/events", headers=headers, json=body).json()["accepted"] == 1
    assert client.post("/api/events", headers=headers, json=body).json()["duplicates"] == 1
    alert = client.get("/api/alerts", headers=headers).json()[0]
    assert alert["severity"] >= 80
    assert any(r["technique"] == "T1098" for r in alert["findings"])
    assert client.post("/api/alerts/iam-test/summary", headers=headers).json()["source"] == "template"

def test_validation(client):
    h = {"X-API-Key": KEY}
    for bad in [event(timestamp="2026-01-01T12:00:00"), event(latitude=30), event(bytes_transferred=-1)]:
        assert client.post("/api/events", headers=h, json={"events": [bad]}).status_code == 422

def test_failed_auth_and_future_exclusion():
    d = Detector()
    e = Event(**event(action="ConsoleLogin", success=False))
    history = [dict(epoch=e.timestamp.timestamp()-i, success=False, action="ConsoleLogin") for i in range(1,5)]
    assert any(r["technique"] == "T1110" for r in d.detect(e, history)[1])
    assert not any(r["technique"] == "T1110" for r in d.detect(e, [dict(h, epoch=e.timestamp.timestamp()+1) for h in history])[1])

def test_travel():
    e = Event(**event(action="ConsoleLogin", latitude=51.5, longitude=-.1))
    history = [dict(epoch=e.timestamp.timestamp()-3600, success=True, action="ConsoleLogin", latitude=40.7, longitude=-74)]
    assert any(r["category"] == "Impossible travel" for r in Detector().detect(e, history)[1])

def test_cloudtrail_failure():
    result = normalize(dict(eventID="x", eventTime="2026-01-01T12:00:00Z", eventName="ConsoleLogin", responseElements={"ConsoleLogin":"Failure"}))
    assert result["success"] is False

def test_model_deterministic_and_bounded():
    e = Event(**event(bytes_transferred=10**12))
    a = Detector().detect(e, [])[0]
    assert a == Detector().detect(e, [])[0]
    assert 0 <= a <= 100

def test_batch_history(client):
    events = [event(event_id=f"failed-{i}", principal="bob", action="ConsoleLogin", success=False,
                    timestamp=f"2026-01-01T12:00:0{i}Z") for i in range(5)]
    h = {"X-API-Key": KEY}
    assert client.post("/api/events", headers=h, json={"events":list(reversed(events))}).json()["accepted"] == 5
    rows = client.get("/api/alerts", headers=h).json()
    last = next(r for r in rows if r["event"]["event_id"] == "failed-4")
    assert any(r["technique"] == "T1110" for r in last["findings"])

def test_llm_fallback(client, monkeypatch):
    import httpx
    monkeypatch.setenv("LLM_ENABLED", "true")
    def offline(*args, **kwargs):
        raise httpx.ConnectError("offline")
    monkeypatch.setattr(httpx.Client, "post", offline)
    # Use request() so the test transport is unaffected by the provider post mock.
    h = {"X-API-Key": KEY}
    client.request("POST", "/api/events", headers=h, json={"events":[event(event_id="llm-fallback", action="CreateAccessKey")]})
    response = client.request("POST", "/api/alerts/llm-fallback/summary", headers=h)
    assert response.json()["source"] == "template_fallback"
    assert "CreateAccessKey" in response.json()["summary"]


def test_llm_summary_excludes_identity(client, monkeypatch):
    import httpx
    monkeypatch.setenv("LLM_ENABLED", "true")
    captured = {}
    def provider(self, url, **kwargs):
        captured.update(kwargs["json"])
        return httpx.Response(200, json={"message":{"content":"Review this IAM change."}}, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx.Client, "post", provider)
    h = {"X-API-Key": KEY}
    client.request("POST", "/api/events", headers=h, json={"events":[event(event_id="llm-success", principal="secret-principal", source_ip="192.0.2.88", action="CreateAccessKey")]})
    response = client.request("POST", "/api/alerts/llm-success/summary", headers=h)
    assert response.json()["source"] == "llm"
    assert "secret-principal" not in str(captured)
    assert "192.0.2.88" not in str(captured)


def test_missing_summary_and_health(client):
    assert client.get("/health").status_code == 200
    assert client.post("/api/alerts/missing/summary", headers={"X-API-Key": KEY}).status_code == 404
    assert "cloudsentinel_events_total" in client.get("/metrics").text
