"""Tests for /v1/events — single-file and multi-file (post-rotation) scenarios."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_shield.api.app import create_app
from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.audit import AuditLog

TEST_API_KEY = "events-api-test-key"
BLOCK_SIZE = 4096


@pytest.fixture(autouse=True)
def patch_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import aegis_shield.api.auth as auth_module

    monkeypatch.setattr(auth_module, "_ACTIVE_KEY", TEST_API_KEY)


def _make_client(journal: DurableJournal, tmp_path: Path) -> TestClient:
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    app = create_app(engine=engine)
    return TestClient(app, raise_server_exceptions=True)


def _auth() -> dict:
    return {"X-API-Key": TEST_API_KEY}


# ---------------------------------------------------------------------------
# Baseline — no rotation
# ---------------------------------------------------------------------------

def test_events_returns_all_events_no_rotation(journal: DurableJournal, tmp_path: Path) -> None:
    """Events from a single unrotated log file are all returned."""
    client = _make_client(journal, tmp_path)
    resp = client.get("/v1/events", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    # Engine writes at least one event on boot (state_transition)
    assert data["total"] >= 1
    assert len(data["events"]) == data["count"]


def test_events_total_matches_event_count(journal: DurableJournal, tmp_path: Path) -> None:
    """total, count, and len(events) are consistent."""
    client = _make_client(journal, tmp_path)
    resp = client.get("/v1/events?limit=1000", headers=_auth())
    data = resp.json()
    assert data["total"] == data["count"]
    assert len(data["events"]) == data["count"]


def test_events_pagination_after(journal: DurableJournal, tmp_path: Path) -> None:
    """after parameter skips the correct number of events."""
    client = _make_client(journal, tmp_path)
    all_resp = client.get("/v1/events?limit=1000", headers=_auth())
    all_events = all_resp.json()["events"]
    total = len(all_events)
    if total < 2:
        pytest.skip("need at least 2 events for pagination test")

    page_resp = client.get("/v1/events?after=1&limit=1000", headers=_auth())
    page_data = page_resp.json()
    assert page_data["events"] == all_events[1:]
    assert page_data["total"] == total  # total is always the grand total


def test_events_limit_respected(journal: DurableJournal, tmp_path: Path) -> None:
    """limit caps the number of returned events."""
    client = _make_client(journal, tmp_path)
    resp = client.get("/v1/events?limit=1", headers=_auth())
    data = resp.json()
    assert len(data["events"]) <= 1


def test_events_requires_auth(journal: DurableJournal, tmp_path: Path) -> None:
    client = _make_client(journal, tmp_path)
    resp = client.get("/v1/events")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Post-rotation — archived events must not be lost
# ---------------------------------------------------------------------------

def test_events_includes_rotated_archives(tmp_path: Path) -> None:
    """Events rotated into audit.N.jsonl are still returned by /v1/events."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    audit_path = tmp_path / "audit.jsonl"

    # Use a tiny max_bytes so every append causes rotation
    log = AuditLog(audit_path, max_bytes=1)
    log.append("rotated_event_a", {"x": 1})
    log.append("rotated_event_b", {"x": 2})
    log.append("rotated_event_c", {"x": 3})

    # Verify archives actually exist
    archives = sorted(tmp_path.glob("audit.*.jsonl"))
    assert archives, "no archive files created — test premise is invalid"

    # Now build an engine that shares the same audit path
    engine = AegisEngine(journal, Policy(PolicyConfig()), audit_path)
    # Replace the engine's audit log with our pre-populated one (same path)
    engine.audit = log

    app = create_app(engine=engine)
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.get("/v1/events?limit=1000", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()

    event_names = [e["event"] for e in data["events"]]
    assert "rotated_event_a" in event_names, "rotated_event_a missing from /v1/events"
    assert "rotated_event_b" in event_names, "rotated_event_b missing from /v1/events"
    assert "rotated_event_c" in event_names, "rotated_event_c missing from /v1/events"


def test_events_chronological_order_across_archives(tmp_path: Path) -> None:
    """Events are returned in archive-number order (oldest archive first)."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    audit_path = tmp_path / "audit.jsonl"

    log = AuditLog(audit_path, max_bytes=1)
    names = ["alpha", "beta", "gamma", "delta"]
    for name in names:
        log.append(name)

    engine = AegisEngine(journal, Policy(PolicyConfig()), audit_path)
    engine.audit = log

    app = create_app(engine=engine)
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.get("/v1/events?limit=1000", headers=_auth())
    data = resp.json()
    returned_names = [e["event"] for e in data["events"] if e["event"] in names]
    # All four must appear and in insertion order
    assert returned_names == names


def test_events_total_spans_all_archives(tmp_path: Path) -> None:
    """total reflects events across all archive files, not just the active file."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    audit_path = tmp_path / "audit.jsonl"

    log = AuditLog(audit_path, max_bytes=1)
    for i in range(5):
        log.append(f"ev_{i}")

    archives = sorted(tmp_path.glob("audit.*.jsonl"))
    assert len(archives) >= 2, "expected at least 2 archive files"

    engine = AegisEngine(journal, Policy(PolicyConfig()), audit_path)
    engine.audit = log

    # Count events in all files *after* the engine has written its boot events.
    all_lines: list[dict] = []
    for path in sorted(archives, key=lambda p: int(p.stem.split(".")[-1])):
        all_lines.extend(json.loads(line) for line in path.read_bytes().splitlines() if line.strip())
    all_lines.extend(json.loads(line) for line in audit_path.read_bytes().splitlines() if line.strip())
    expected_total = len(all_lines)

    app = create_app(engine=engine)
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.get("/v1/events?limit=1000", headers=_auth())
    data = resp.json()
    assert data["total"] == expected_total
