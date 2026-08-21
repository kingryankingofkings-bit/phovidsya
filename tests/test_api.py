"""REST API tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_shield.api.app import create_app
from aegis_shield.api.auth import get_active_key
from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig


TEST_API_KEY = "test-api-key-for-tests-only"


@pytest.fixture(autouse=True)
def patch_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import aegis_shield.api.auth as auth_module
    monkeypatch.setattr(auth_module, "_ACTIVE_KEY", TEST_API_KEY)


@pytest.fixture()
def client(journal: DurableJournal, tmp_path: Path) -> TestClient:
    policy = Policy(PolicyConfig())
    engine = AegisEngine(journal, policy, tmp_path / "audit.jsonl")
    app = create_app(engine=engine)
    return TestClient(app, raise_server_exceptions=True)


def auth_headers() -> dict:
    return {"X-API-Key": TEST_API_KEY}


def test_health_no_auth(client: TestClient) -> None:
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "state" in data


def test_status_returns_200(client: TestClient) -> None:
    resp = client.get("/v1/status", headers=auth_headers())
    assert resp.status_code == 200


def test_status_correct_fields(client: TestClient) -> None:
    resp = client.get("/v1/status", headers=auth_headers())
    data = resp.json()
    assert "device_id" in data
    assert "state" in data
    assert "state_version" in data
    assert "writes_allowed" in data
    assert "journal_capacity_blocks" in data
    assert data["writes_allowed"] is True
    assert data["state"] == "normal"


def test_status_requires_api_key(client: TestClient) -> None:
    resp = client.get("/v1/status")
    assert resp.status_code == 401


def test_status_rejects_wrong_key(client: TestClient) -> None:
    resp = client.get("/v1/status", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


def test_events_returns_event_list(client: TestClient) -> None:
    resp = client.get("/v1/events", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "total" in data
    assert isinstance(data["events"], list)


def test_events_pagination(client: TestClient) -> None:
    resp = client.get("/v1/events?after=0&limit=5", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["after"] == 0
    assert len(data["events"]) <= 5


def test_challenge_returns_id(client: TestClient) -> None:
    resp = client.post("/v1/challenge", json={"action": "enter_recovery_read_only"}, headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "challenge_id" in data
    assert data["action"] == "enter_recovery_read_only"
    assert "device_id" in data
    assert "expires_at" in data


def test_challenge_requires_auth(client: TestClient) -> None:
    resp = client.post("/v1/challenge", json={"action": "test"})
    assert resp.status_code == 401


def test_sizing_returns_calculations(client: TestClient) -> None:
    resp = client.get("/v1/sizing", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "pcie_encoding_ceiling_bytes_s" in data
    assert "payload_iops_ceiling" in data
    assert "ideal_journal_seconds" in data
    assert "maximum_pending_blocks" in data
    assert data["pcie_encoding_ceiling_bytes_s"] > 0
