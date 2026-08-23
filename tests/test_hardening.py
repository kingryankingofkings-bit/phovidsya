"""Regression tests for the hardening pass.

Each test pins one defect found in the build review so it cannot return.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import aegis_shield.api.auth as auth_module
from aegis_shield.api.app import create_app
from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.features import AnalyzerConfig, WindowAnalyzer
from aegis_shield.core.tokens import (
    RecoveryAuthorization,
    TokenVerifier,
    generate_keypair,
    sign_authorization,
)
from aegis_shield.core.types import IoEvent, IoKind

BLOCK_SIZE = 4096
TEST_API_KEY = "hardening-test-key"


@pytest.fixture(autouse=True)
def patch_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_module, "_ACTIVE_KEY", TEST_API_KEY)


def _headers() -> dict:
    return {"X-API-Key": TEST_API_KEY}


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    return TestClient(create_app(engine=engine), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# F-13 — a non-ASCII API key must be rejected, not crash the request
# ---------------------------------------------------------------------------

def test_non_ascii_api_key_is_unauthorized_not_a_crash() -> None:
    auth_module._ACTIVE_KEY = TEST_API_KEY
    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_module.require_api_key("bad-key-\xff"))
    assert exc.value.status_code == 401


def test_correct_api_key_still_accepted() -> None:
    auth_module._ACTIVE_KEY = TEST_API_KEY
    assert asyncio.run(auth_module.require_api_key(TEST_API_KEY)) == TEST_API_KEY


def test_key_fingerprint_does_not_reveal_the_key() -> None:
    fp = auth_module.key_fingerprint("super-secret-key")
    assert "super-secret-key" not in fp
    assert len(fp) == 12


# ---------------------------------------------------------------------------
# F-09 — export must contain exactly the history it claims
# ---------------------------------------------------------------------------

def test_export_truncates_at_target_sequence(client: TestClient) -> None:
    engine = client.app.state.engine
    engine.write(0, b"BEFORE".ljust(BLOCK_SIZE, b"."))   # sequence 1
    engine.write(1, b"AFTER".ljust(BLOCK_SIZE, b"."))    # sequence 2

    data = client.post(
        "/v1/recovery/export", json={"target_sequence": 1}, headers=_headers()
    ).json()
    log = (Path(data["snapshot_path"]) / "journal.jsonl").read_bytes()
    records = [json.loads(line) for line in log.splitlines() if line.strip()]

    assert [r["sequence"] for r in records] == [1]
    assert b"AFTER" not in log


def test_exported_bundle_is_a_valid_journal(client: TestClient) -> None:
    """A truncated bundle must still replay and verify as a journal."""
    engine = client.app.state.engine
    for i in range(4):
        engine.write(i, bytes([65 + i]) * BLOCK_SIZE)

    data = client.post(
        "/v1/recovery/export", json={"target_sequence": 2}, headers=_headers()
    ).json()
    reopened = DurableJournal(Path(data["snapshot_path"]))
    assert reopened.last_sequence == 2


def test_full_export_still_contains_everything(client: TestClient) -> None:
    engine = client.app.state.engine
    engine.write(0, b"X" * BLOCK_SIZE)
    engine.write(1, b"Y" * BLOCK_SIZE)

    data = client.post("/v1/recovery/export", json={}, headers=_headers()).json()
    reopened = DurableJournal(Path(data["snapshot_path"]))
    assert reopened.last_sequence == engine.journal.last_sequence


# ---------------------------------------------------------------------------
# F-14 — repeated exports must not collide or leak paths
# ---------------------------------------------------------------------------

def test_repeated_exports_same_sequence_all_succeed(client: TestClient) -> None:
    client.app.state.engine.write(0, b"Z" * BLOCK_SIZE)
    names = set()
    for _ in range(3):
        resp = client.post(
            "/v1/recovery/export", json={"target_sequence": 1}, headers=_headers()
        )
        assert resp.status_code == 200, resp.text
        names.add(resp.json()["snapshot_name"])
    assert len(names) == 3


def test_export_error_does_not_leak_filesystem_paths(client: TestClient) -> None:
    resp = client.post(
        "/v1/recovery/export", json={"target_sequence": 9999}, headers=_headers()
    )
    assert resp.status_code == 400
    assert "/" not in resp.json()["detail"]


# ---------------------------------------------------------------------------
# F-15 / F-32 — bounded snapshots and bounded challenge store
# ---------------------------------------------------------------------------

def test_snapshot_count_is_capped(client: TestClient) -> None:
    from aegis_shield.api.routers.recovery import _MAX_SNAPSHOTS

    codes = [
        client.post("/v1/recovery/export", json={}, headers=_headers()).status_code
        for _ in range(_MAX_SNAPSHOTS + 2)
    ]
    assert 507 in codes, "export should refuse once the snapshot cap is reached"


def test_challenge_store_is_bounded_and_per_app(client: TestClient) -> None:
    from aegis_shield.api.routers.recovery import _MAX_CHALLENGES

    for _ in range(_MAX_CHALLENGES + 50):
        client.post(
            "/v1/challenge",
            json={"action": "enter_recovery_read_only"},
            headers=_headers(),
        )
    assert len(client.app.state.challenges) <= _MAX_CHALLENGES


def test_challenge_rejects_unknown_action(client: TestClient) -> None:
    resp = client.post("/v1/challenge", json={"action": "do-whatever"}, headers=_headers())
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# F-11 / F-26 — security headers and the dashboard route
# ---------------------------------------------------------------------------

def test_security_headers_present(client: TestClient) -> None:
    resp = client.get("/v1/health")
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_root_redirects_to_dashboard(client: TestClient) -> None:
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (307, 308)
    assert resp.headers["location"] == "/ui/"


def test_dashboard_builds_rows_without_html_interpolation() -> None:
    """The XSS sink must stay closed: no HTML string building in renderEvents."""
    js = (Path(__file__).parent.parent / "web" / "static" / "dashboard.js").read_text()
    body = js.split("function renderEvents")[1].split("\nfunction ")[0]
    assert "insertAdjacentHTML" not in body
    assert "innerHTML" not in body
    assert "textContent" in body


# ---------------------------------------------------------------------------
# F-16 — the written-block census must stay bounded to the window
# ---------------------------------------------------------------------------

def test_written_block_census_is_bounded() -> None:
    analyzer = WindowAnalyzer(AnalyzerConfig(window_operations=16, namespace_blocks=4096))
    for lba in range(500):
        analyzer.observe(IoEvent(IoKind.WRITE, lba, 1, b"\x00" * BLOCK_SIZE, 0))
    assert len(analyzer._written_blocks) <= 16


def test_overwrite_fraction_does_not_saturate_over_time() -> None:
    """Old writes must stop counting, or every workload eventually reads as overwrite."""
    analyzer = WindowAnalyzer(AnalyzerConfig(window_operations=16, namespace_blocks=4096))
    for lba in range(200):
        analyzer.observe(IoEvent(IoKind.WRITE, lba, 1, b"\x00" * BLOCK_SIZE, 0))
    assert analyzer.snapshot().overwrite_fraction < 0.5


def test_genuine_overwrite_is_still_detected() -> None:
    analyzer = WindowAnalyzer(AnalyzerConfig(window_operations=64, namespace_blocks=4096))
    for _ in range(20):
        analyzer.observe(IoEvent(IoKind.WRITE, 7, 1, b"\x00" * BLOCK_SIZE, 0))
    assert analyzer.snapshot().overwrite_fraction > 0.5


# ---------------------------------------------------------------------------
# F-17 — nonces must be pruned once their tokens can no longer be valid
# ---------------------------------------------------------------------------

def test_expired_nonces_are_pruned() -> None:
    now = int(time.time())
    pruned = AegisEngine._prune_nonces({"fresh": now + 300, "stale": now - 10}, now=now)
    assert "fresh" in pruned and "stale" not in pruned


def test_legacy_nonce_list_is_migrated() -> None:
    now = int(time.time())
    pruned = AegisEngine._prune_nonces(["old-a", "old-b"], now=now)
    assert set(pruned) == {"old-a", "old-b"}
    assert all(expiry > now for expiry in pruned.values())


def test_nonce_replay_still_rejected_after_pruning(tmp_path: Path) -> None:
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    verifier = TokenVerifier(pub.read_bytes())

    nonce = secrets.token_hex(16)

    def token() -> str:
        now = int(time.time())
        return sign_authorization(
            RecoveryAuthorization(
                action="enter_maintenance",
                device_id=journal.device_id,
                expires_unix=now + 300,
                issued_unix=now,
                nonce=nonce,
                state_version=engine.state_version,
            ),
            priv.read_bytes(),
        )

    engine.enter_maintenance(token(), verifier, physical_presence=True)
    engine.exit_maintenance()
    with pytest.raises(ValueError, match="nonce already used"):
        engine.enter_maintenance(token(), verifier, physical_presence=True)


# ---------------------------------------------------------------------------
# F-03 — compaction must be refused during an incident
# ---------------------------------------------------------------------------

def test_compaction_refused_while_contained(tmp_path: Path) -> None:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    engine.write(0, b"A" * BLOCK_SIZE)
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")

    with pytest.raises(RuntimeError, match="compaction refused"):
        engine.compact_journal()
    assert (tmp_path / "ns" / "journal.jsonl").stat().st_size > 0


def test_compaction_refused_in_recovery_and_reads_survive(tmp_path: Path) -> None:
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    engine.write(0, b"EVIDENCE".ljust(BLOCK_SIZE, b"."))
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")

    now = int(time.time())
    engine.authorize_recovery(
        sign_authorization(
            RecoveryAuthorization(
                action="enter_recovery_read_only",
                device_id=journal.device_id,
                expires_unix=now + 120,
                issued_unix=now,
                nonce=secrets.token_hex(16),
                state_version=engine.state_version,
                target_sequence=journal.last_sequence,
            ),
            priv.read_bytes(),
        ),
        TokenVerifier(pub.read_bytes()),
        physical_presence=True,
    )

    with pytest.raises(RuntimeError, match="compaction refused"):
        engine.compact_journal()
    assert engine.read(0).startswith(b"EVIDENCE")


def test_compaction_allowed_in_normal_and_clears_anchors(tmp_path: Path) -> None:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    engine.write(0, b"KEEP".ljust(BLOCK_SIZE, b"."))

    name = engine.compact_journal()
    assert (journal.root / "snapshots" / name).exists()
    assert engine.containment_sequence is None and engine.recovery_sequence is None
    assert engine.read(0).startswith(b"KEEP"), "compaction must preserve the logical image"


# ---------------------------------------------------------------------------
# F-06 — containment is enabled by default
# ---------------------------------------------------------------------------

def test_containment_enabled_by_default() -> None:
    assert PolicyConfig().containment_enabled is True


# ---------------------------------------------------------------------------
# F-24 — concurrent mutation must not break either hash chain
# ---------------------------------------------------------------------------

def test_concurrent_writes_keep_both_hash_chains_valid(tmp_path: Path) -> None:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=256, block_size=BLOCK_SIZE)
    engine = AegisEngine(
        journal, Policy(PolicyConfig(containment_enabled=False)), tmp_path / "audit.jsonl"
    )

    errors: list[Exception] = []

    def hammer(base: int) -> None:
        try:
            for i in range(25):
                engine.write((base * 25 + i) % 256, bytes([base % 251]) * BLOCK_SIZE)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent writes raised: {errors}"
    engine.audit.verify()                      # audit chain intact
    DurableJournal(journal.root)               # journal replays and verifies
