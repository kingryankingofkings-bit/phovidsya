"""Containment must survive attacks on the persisted engine state (F-01, F-22).

The engine records the SHA-256 of every persisted state in the hash-chained
audit log.  Deleting, corrupting, or forging the state file must drive the
engine into FAULT with writes denied — never into a fresh NORMAL boot, which
would release containment with no token, no nonce, and no physical presence.
"""

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


@pytest.fixture()
def keypair(tmp_path: Path):
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    return priv, pub


def _contained_engine(tmp_path: Path) -> AegisEngine:
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")
    assert engine.state.value == "contained"
    return engine


def _reopen(tmp_path: Path) -> AegisEngine:
    return AegisEngine(
        DurableJournal(tmp_path / "ns"), Policy(PolicyConfig()), tmp_path / "audit.jsonl"
    )


def _audit_events(tmp_path: Path) -> list[str]:
    raw = (tmp_path / "audit.jsonl").read_bytes().splitlines()
    return [json.loads(line)["event"] for line in raw if line.strip()]


# ---------------------------------------------------------------------------
# The three attacks on the state file
# ---------------------------------------------------------------------------

def test_deleting_state_file_does_not_release_containment(tmp_path: Path) -> None:
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").unlink()

    engine = _reopen(tmp_path)
    assert engine.state.value == "fault"
    assert engine.status()["writes_allowed"] is False


def test_corrupting_state_file_does_not_release_containment(tmp_path: Path) -> None:
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").write_bytes(b"{ not json")

    engine = _reopen(tmp_path)
    assert engine.state.value == "fault"
    assert engine.status()["writes_allowed"] is False


def test_forged_normal_state_is_rejected(tmp_path: Path) -> None:
    """A syntactically valid state file with no matching digest must be refused."""
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").write_bytes(
        json.dumps(
            {
                "state": "normal",
                "state_version": 99,
                "containment_sequence": None,
                "recovery_sequence": None,
                "used_nonces": {},
            },
            sort_keys=True,
            indent=2,
        ).encode()
        + b"\n"
    )

    engine = _reopen(tmp_path)
    assert engine.state.value == "fault"
    assert engine.status()["writes_allowed"] is False


def test_fault_entry_is_audited(tmp_path: Path) -> None:
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").unlink()
    _reopen(tmp_path)

    assert "fault_entered" in _audit_events(tmp_path)


def test_writes_are_denied_in_fault(tmp_path: Path) -> None:
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").unlink()
    engine = _reopen(tmp_path)

    with pytest.raises(PermissionError):
        engine.write(0, b"X" * BLOCK_SIZE)


def test_reads_still_work_in_fault(tmp_path: Path) -> None:
    """FAULT denies writes but must not destroy forensic read access."""
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").unlink()
    engine = _reopen(tmp_path)

    assert len(engine.read(0)) == BLOCK_SIZE


# ---------------------------------------------------------------------------
# Legitimate paths must still work
# ---------------------------------------------------------------------------

def test_untampered_state_restores_normally(tmp_path: Path) -> None:
    """The digest check must not break ordinary restart persistence."""
    _contained_engine(tmp_path)
    engine = _reopen(tmp_path)
    assert engine.state.value == "contained"
    assert engine.status()["writes_allowed"] is False


def test_first_boot_with_no_state_is_normal(tmp_path: Path) -> None:
    """Genuinely absent state is a first boot, not a tampering event."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")
    assert engine.state.value == "normal"


def test_fault_exits_only_through_authorized_maintenance(tmp_path: Path, keypair) -> None:
    priv, pub = keypair
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").unlink()
    engine = _reopen(tmp_path)
    assert engine.state.value == "fault"

    now = int(time.time())
    auth = RecoveryAuthorization(
        action="enter_maintenance",
        device_id=engine.journal.device_id,
        expires_unix=now + 120,
        issued_unix=now,
        nonce=secrets.token_hex(16),
        state_version=engine.state_version,
    )
    engine.enter_maintenance(
        sign_authorization(auth, priv.read_bytes()),
        TokenVerifier(pub.read_bytes()),
        physical_presence=True,
    )
    engine.exit_maintenance()

    assert engine.state.value == "normal"
    assert engine.status()["writes_allowed"] is True


def test_fault_cannot_be_left_without_a_token(tmp_path: Path) -> None:
    _contained_engine(tmp_path)
    (tmp_path / "ns" / "engine_state.json").unlink()
    engine = _reopen(tmp_path)

    with pytest.raises(RuntimeError):
        engine.exit_maintenance()
    assert engine.state.value == "fault"
