"""Tests for engine state persistence across restarts and nonce replay protection."""

from __future__ import annotations

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


def _text_block(text: str = "hello") -> bytes:
    return (text * (BLOCK_SIZE // len(text) + 1))[:BLOCK_SIZE].encode("ascii")


def _make_engine(journal: DurableJournal, tmp_path: Path) -> AegisEngine:
    return AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")


def _reopen_engine(journal_root: Path, tmp_path: Path) -> AegisEngine:
    """Simulate a daemon restart by opening the same journal root."""
    journal = DurableJournal(journal_root)
    return AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")


# ── State file present after transitions ──────────────────────────────────────────────

def test_state_file_created_on_init(tmp_path: Path) -> None:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    _make_engine(journal, tmp_path)
    state_file = tmp_path / "ns" / "engine_state.json"
    assert state_file.exists(), "engine_state.json must be written on init"


def test_normal_state_survives_restart(tmp_path: Path) -> None:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    eng = _make_engine(journal, tmp_path)
    assert eng.state.value == "normal"

    eng2 = _reopen_engine(tmp_path / "ns", tmp_path)
    assert eng2.state.value == "normal"
    assert eng2.state_version == eng.state_version


def test_contained_state_survives_restart(tmp_path: Path) -> None:
    """After containment the restarted engine must come up in CONTAINED, not NORMAL."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    eng = _make_engine(journal, tmp_path)
    eng.write(0, _text_block("before"))
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")
    assert eng.state.value == "contained"
    containment_seq = eng.containment_sequence
    sv = eng.state_version

    eng2 = _reopen_engine(tmp_path / "ns", tmp_path)
    assert eng2.state.value == "contained", "restarted engine must stay CONTAINED"
    assert eng2.containment_sequence == containment_seq
    assert eng2.state_version == sv


def test_writes_blocked_after_restart_contained(tmp_path: Path) -> None:
    """Writes must still be blocked after a restart that restores CONTAINED state."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    eng = _make_engine(journal, tmp_path)
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")

    eng2 = _reopen_engine(tmp_path / "ns", tmp_path)
    with pytest.raises(PermissionError):
        eng2.write(0, _text_block())


# ── Nonce replay protection across restarts ─────────────────────────────────────────────

def test_used_nonce_persisted_and_rejected_after_restart(tmp_path: Path) -> None:
    """A nonce consumed before restart must still be rejected after restart."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    eng = _make_engine(journal, tmp_path)
    eng.write(0, _text_block("before"))
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")

    priv_pem = tmp_path / "priv.pem"
    pub_pem = tmp_path / "pub.pem"
    generate_keypair(priv_pem, pub_pem)

    now = int(time.time())
    nonce = secrets.token_hex(16)
    authorization = RecoveryAuthorization(
        action="enter_recovery_read_only",
        device_id=journal.device_id,
        expires_unix=now + 300,
        issued_unix=now,
        nonce=nonce,
        state_version=eng.state_version,
        target_sequence=journal.last_sequence,
    )
    token = sign_authorization(authorization, priv_pem.read_bytes())
    verifier = TokenVerifier(pub_pem.read_bytes())

    # Use the token once on the first engine instance
    eng.authorize_recovery(token, verifier, physical_presence=True, now=now)
    assert eng.state.value == "recovery_read_only"

    # Reopen — the engine must be in RECOVERY_READ_ONLY and the nonce still burned.
    # (We can't re-authorize because we're already past CONTAINED, so we test the
    #  nonce set itself.)
    eng2 = _reopen_engine(tmp_path / "ns", tmp_path)
    assert eng2.state.value == "recovery_read_only"
    assert nonce in eng2._used_nonces, "used nonce must survive a restart"


# ── Unix socket physical-presence authorization ──────────────────────────────────────────

def test_daemon_socket_authorize(tmp_path: Path) -> None:
    """AegisDaemon._socket_authorize() must complete recovery with physical_presence=True."""
    from aegis_shield.daemon.service import AegisDaemon

    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    eng = _make_engine(journal, tmp_path)
    eng.write(0, _text_block("before"))
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")

    priv_pem = tmp_path / "priv.pem"
    pub_pem = tmp_path / "pub.pem"
    generate_keypair(priv_pem, pub_pem)

    now = int(time.time())
    authorization = RecoveryAuthorization(
        action="enter_recovery_read_only",
        device_id=journal.device_id,
        expires_unix=now + 300,
        issued_unix=now,
        nonce=secrets.token_hex(16),
        state_version=eng.state_version,
        target_sequence=journal.last_sequence,
    )
    token = sign_authorization(authorization, priv_pem.read_bytes())

    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=pub_pem,
    )
    import json
    result = json.loads(daemon._socket_authorize(token, eng))
    assert result.get("authorized") is True
    assert eng.state.value == "recovery_read_only"


def test_daemon_socket_authorize_no_pubkey(tmp_path: Path) -> None:
    """_socket_authorize must fail gracefully when no public key is configured."""
    from aegis_shield.daemon.service import AegisDaemon

    journal = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BLOCK_SIZE)
    eng = _make_engine(journal, tmp_path)
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")

    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=None,  # deliberately omitted
    )
    import json
    result = json.loads(daemon._socket_authorize("fake-token", eng))
    assert "error" in result
    assert result.get("authorized") is not True
