"""Tests for maintenance state entry/exit and journal compaction."""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

import pytest

from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.tokens import (
    RecoveryAuthorization,
    TokenVerifier,
    generate_keypair,
    sign_authorization,
)

BLOCK_SIZE = 4096


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text_block(text: str = "hello") -> bytes:
    return (text * (BLOCK_SIZE // len(text) + 1))[:BLOCK_SIZE].encode("ascii")


def _make_engine(journal: DurableJournal, tmp_path: Path) -> AegisEngine:
    return AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")


@pytest.fixture()
def keypair(tmp_path: Path):
    priv = tmp_path / "key.pem"
    pub = tmp_path / "key.pub"
    generate_keypair(priv, pub)
    return priv, pub


def _maintenance_token(
    engine: AegisEngine,
    private_pem: bytes,
    *,
    nonce: str | None = None,
    ttl: int = 120,
    action: str = "enter_maintenance",
) -> str:
    now = int(time.time())
    auth = RecoveryAuthorization(
        action=action,
        device_id=engine.journal.device_id,
        expires_unix=now + ttl,
        issued_unix=now,
        nonce=nonce or secrets.token_hex(16),
        state_version=engine.state_version,
    )
    return sign_authorization(auth, private_pem)


def _contain(engine: AegisEngine) -> None:
    """Drive the engine into CONTAINED state."""
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")


# ---------------------------------------------------------------------------
# enter_maintenance — valid paths
# ---------------------------------------------------------------------------

def test_enter_maintenance_from_normal(tmp_path: Path, keypair) -> None:
    """NORMAL → MAINTENANCE with a valid token and physical presence."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    assert engine.state.value == "normal"

    token = _maintenance_token(engine, priv.read_bytes())
    verifier = TokenVerifier(pub.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    assert engine.state.value == "maintenance"


def test_enter_maintenance_from_contained(tmp_path: Path, keypair) -> None:
    """CONTAINED → MAINTENANCE with a valid token."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    _contain(engine)
    assert engine.state.value == "contained"

    token = _maintenance_token(engine, priv.read_bytes())
    verifier = TokenVerifier(pub.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    assert engine.state.value == "maintenance"


def test_enter_maintenance_from_recovery_read_only(tmp_path: Path, keypair) -> None:
    """RECOVERY_READ_ONLY → MAINTENANCE."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    _contain(engine)
    verifier = TokenVerifier(pub.read_bytes())

    # First get into recovery_read_only via authorize_recovery
    recovery_auth = RecoveryAuthorization(
        action="enter_recovery_read_only",
        device_id=journal.device_id,
        expires_unix=int(time.time()) + 120,
        issued_unix=int(time.time()),
        nonce=secrets.token_hex(16),
        state_version=engine.state_version,
        target_sequence=journal.last_sequence,
    )
    recovery_token = sign_authorization(recovery_auth, priv.read_bytes())
    engine.authorize_recovery(recovery_token, verifier, physical_presence=True)
    assert engine.state.value == "recovery_read_only"

    maint_token = _maintenance_token(engine, priv.read_bytes())
    engine.enter_maintenance(maint_token, verifier, physical_presence=True)
    assert engine.state.value == "maintenance"


# ---------------------------------------------------------------------------
# enter_maintenance — rejection paths
# ---------------------------------------------------------------------------

def test_enter_maintenance_requires_physical_presence(tmp_path: Path, keypair) -> None:
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)

    token = _maintenance_token(engine, priv.read_bytes())
    verifier = TokenVerifier(pub.read_bytes())
    with pytest.raises(PermissionError):
        engine.enter_maintenance(token, verifier, physical_presence=False)


def test_enter_maintenance_wrong_action_rejected(tmp_path: Path, keypair) -> None:
    """Token signed for a different action must be refused."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)

    bad_token = _maintenance_token(engine, priv.read_bytes(), action="enter_recovery_read_only")
    verifier = TokenVerifier(pub.read_bytes())
    with pytest.raises(ValueError):
        engine.enter_maintenance(bad_token, verifier, physical_presence=True)


def test_enter_maintenance_nonce_replay_rejected(tmp_path: Path, keypair) -> None:
    """Re-using a nonce must raise ValueError."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    verifier = TokenVerifier(pub.read_bytes())

    nonce = secrets.token_hex(16)
    token = _maintenance_token(engine, priv.read_bytes(), nonce=nonce)
    engine.enter_maintenance(token, verifier, physical_presence=True)

    # Return to normal so we can try again
    engine.exit_maintenance()

    # Re-use same nonce on next enter — must fail even though action and version match
    token2 = _maintenance_token(engine, priv.read_bytes(), nonce=nonce)
    with pytest.raises(ValueError, match="nonce already used"):
        engine.enter_maintenance(token2, verifier, physical_presence=True)


# ---------------------------------------------------------------------------
# exit_maintenance
# ---------------------------------------------------------------------------

def test_exit_maintenance_returns_to_normal(tmp_path: Path, keypair) -> None:
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    verifier = TokenVerifier(pub.read_bytes())

    token = _maintenance_token(engine, priv.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    engine.exit_maintenance()
    assert engine.state.value == "normal"


def test_exit_maintenance_clears_sequences(tmp_path: Path, keypair) -> None:
    """containment_sequence and recovery_sequence are cleared on exit."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    _contain(engine)
    verifier = TokenVerifier(pub.read_bytes())
    assert engine.containment_sequence is not None

    token = _maintenance_token(engine, priv.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    engine.exit_maintenance()
    assert engine.containment_sequence is None
    assert engine.recovery_sequence is None


def test_exit_maintenance_writes_allowed(tmp_path: Path, keypair) -> None:
    """Writes must succeed after exit_maintenance returns to NORMAL."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    _contain(engine)
    verifier = TokenVerifier(pub.read_bytes())

    token = _maintenance_token(engine, priv.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    engine.exit_maintenance()
    # Should not raise
    engine.write(0, _text_block("post-maintenance"))


def test_exit_maintenance_from_wrong_state_raises(tmp_path: Path) -> None:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    with pytest.raises(RuntimeError, match="must be in maintenance"):
        engine.exit_maintenance()


# ---------------------------------------------------------------------------
# exit_maintenance with compact=True
# ---------------------------------------------------------------------------

def test_exit_maintenance_compact_creates_snapshot(tmp_path: Path, keypair) -> None:
    """exit_maintenance(compact=True) materialises a new base image."""
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    engine.write(0, _text_block("before"))
    verifier = TokenVerifier(pub.read_bytes())

    token = _maintenance_token(engine, priv.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    snapshot_name = engine.exit_maintenance(compact=True)

    assert snapshot_name is not None
    snapshot_path = journal.root / "snapshots" / snapshot_name
    assert snapshot_path.exists(), "snapshot directory must be created"
    assert engine.state.value == "normal"


def test_exit_maintenance_no_compact_returns_none(tmp_path: Path, keypair) -> None:
    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    verifier = TokenVerifier(pub.read_bytes())

    token = _maintenance_token(engine, priv.read_bytes())
    engine.enter_maintenance(token, verifier, physical_presence=True)
    result = engine.exit_maintenance(compact=False)
    assert result is None


# ---------------------------------------------------------------------------
# Socket commands
# ---------------------------------------------------------------------------

def _send_socket_command(command: str, engine: AegisEngine, daemon) -> dict:
    response = daemon._handle_socket_command(command, engine)
    return json.loads(response)


def test_socket_maintenance_command(tmp_path: Path, keypair) -> None:
    """'maintenance <token>' via socket transitions to MAINTENANCE."""
    from aegis_shield.daemon.service import AegisDaemon

    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)

    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=pub,
    )

    token = _maintenance_token(engine, priv.read_bytes())
    result = _send_socket_command(f"maintenance {token}", engine, daemon)
    assert result.get("maintenance") is True
    assert result.get("state") == "maintenance"


def test_socket_exit_maintenance_command(tmp_path: Path, keypair) -> None:
    """'exit-maintenance' via socket returns to NORMAL."""
    from aegis_shield.daemon.service import AegisDaemon

    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)

    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=pub,
    )

    token = _maintenance_token(engine, priv.read_bytes())
    _send_socket_command(f"maintenance {token}", engine, daemon)

    result = _send_socket_command("exit-maintenance", engine, daemon)
    assert result.get("state") == "normal"
    assert "compacted_snapshot" not in result


def test_socket_exit_maintenance_compact_command(tmp_path: Path, keypair) -> None:
    """'exit-maintenance compact' compacts the journal and returns snapshot name."""
    from aegis_shield.daemon.service import AegisDaemon

    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    engine.write(0, _text_block("data"))

    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=pub,
    )

    token = _maintenance_token(engine, priv.read_bytes())
    _send_socket_command(f"maintenance {token}", engine, daemon)

    result = _send_socket_command("exit-maintenance compact", engine, daemon)
    assert result.get("state") == "normal"
    assert "compacted_snapshot" in result
    snapshot_path = journal.root / "snapshots" / result["compacted_snapshot"]
    assert snapshot_path.exists()


def test_socket_compact_command(tmp_path: Path, keypair) -> None:
    """'compact' via socket compacts the journal without entering maintenance."""
    from aegis_shield.daemon.service import AegisDaemon

    priv, pub = keypair
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    engine.write(0, _text_block("data"))

    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=pub,
    )

    result = _send_socket_command("compact", engine, daemon)
    assert result.get("compacted") is True
    assert "snapshot_name" in result
    snapshot_path = journal.root / "snapshots" / result["snapshot_name"]
    assert snapshot_path.exists()


def test_socket_maintenance_no_public_key(tmp_path: Path) -> None:
    """'maintenance' without a configured public key returns an error."""
    from aegis_shield.daemon.service import AegisDaemon

    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    engine = _make_engine(journal, tmp_path)
    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
    )

    result = _send_socket_command("maintenance fake-token", engine, daemon)
    assert "error" in result
    assert result.get("maintenance") is not True
