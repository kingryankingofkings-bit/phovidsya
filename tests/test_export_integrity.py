"""Tests for recovery export integrity manifest (gap #7)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_shield.api.app import create_app
from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig

TEST_API_KEY = "export-integrity-test-key"


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _do_export(client: TestClient) -> dict:
    resp = client.post("/v1/recovery/export", json={}, headers=auth_headers())
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_export_returns_integrity_sha256(client: TestClient) -> None:
    """Response includes a 64-character hex integrity_sha256 field."""
    data = _do_export(client)
    assert "integrity_sha256" in data
    h = data["integrity_sha256"]
    assert isinstance(h, str) and len(h) == 64
    int(h, 16)  # must be valid hex


def test_export_manifest_file_exists(client: TestClient) -> None:
    """manifest.json is written inside the snapshot directory."""
    data = _do_export(client)
    manifest_path = Path(data["snapshot_path"]) / "manifest.json"
    assert manifest_path.exists(), "manifest.json missing from snapshot"


def test_export_manifest_is_valid_json(client: TestClient) -> None:
    """manifest.json is well-formed JSON with required top-level keys."""
    data = _do_export(client)
    manifest = json.loads((Path(data["snapshot_path"]) / "manifest.json").read_bytes())
    for key in ("device_id", "exported_at_ns", "files", "snapshot_name", "target_sequence"):
        assert key in manifest, f"missing key {key!r} in manifest"


def test_export_manifest_covers_snapshot_files(client: TestClient) -> None:
    """Every filename listed under manifest['files'] exists in the snapshot directory."""
    data = _do_export(client)
    snapshot_path = Path(data["snapshot_path"])
    manifest = json.loads((snapshot_path / "manifest.json").read_bytes())
    for filename in manifest["files"]:
        assert (snapshot_path / filename).exists(), f"{filename} listed in manifest but missing"


def test_export_file_hashes_are_correct(client: TestClient) -> None:
    """Re-hashing each file in the snapshot matches the hash recorded in manifest.json."""
    data = _do_export(client)
    snapshot_path = Path(data["snapshot_path"])
    manifest = json.loads((snapshot_path / "manifest.json").read_bytes())
    for filename, expected_hash in manifest["files"].items():
        actual_hash = hashlib.sha256((snapshot_path / filename).read_bytes()).hexdigest()
        assert actual_hash == expected_hash, f"{filename}: hash mismatch (tamper detected)"


def test_export_integrity_sha256_matches_manifest_bytes(client: TestClient) -> None:
    """integrity_sha256 in the response equals SHA-256(manifest.json bytes)."""
    data = _do_export(client)
    snapshot_path = Path(data["snapshot_path"])
    manifest_bytes = (snapshot_path / "manifest.json").read_bytes()
    expected = hashlib.sha256(manifest_bytes).hexdigest()
    assert data["integrity_sha256"] == expected


def test_tampered_file_detected_by_rehash(client: TestClient) -> None:
    """Mutating a snapshot file causes its re-computed hash to diverge from the manifest."""
    data = _do_export(client)
    snapshot_path = Path(data["snapshot_path"])
    manifest = json.loads((snapshot_path / "manifest.json").read_bytes())

    # Corrupt one of the snapshot data files
    data_files = [f for f in sorted(snapshot_path.iterdir()) if f.name != "manifest.json"]
    assert data_files, "no data files to tamper with"
    target = data_files[0]
    original_content = target.read_bytes()
    target.write_bytes(original_content + b"\x00corrupted")

    # Re-hash should diverge from manifest
    actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    assert actual_hash != manifest["files"][target.name], "tamper should produce a different hash"


def test_export_audit_event_recorded(client: TestClient, tmp_path: Path) -> None:
    """A recovery_export audit event is written with the integrity hash."""
    data = _do_export(client)
    integrity = data["integrity_sha256"]

    audit_path = tmp_path / "audit.jsonl"
    events = [json.loads(line) for line in audit_path.read_bytes().splitlines() if line.strip()]
    export_events = [e for e in events if e.get("event") == "recovery_export"]
    assert export_events, "no recovery_export event found in audit log"
    assert export_events[-1]["details"]["integrity_sha256"] == integrity


def test_export_requires_auth(client: TestClient) -> None:
    """POST /v1/recovery/export returns 401 without an API key."""
    resp = client.post("/v1/recovery/export", json={})
    assert resp.status_code == 401
