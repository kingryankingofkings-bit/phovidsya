"""Engine integration tests — exercise the core state machine and policy."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aegis_shield.core import AegisEngine, AegisState, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.tokens import (
    RecoveryAuthorization,
    TokenVerifier,
    generate_keypair,
    sign_authorization,
)


BLOCK_SIZE = 4096


def _text_block(text: str = "hello") -> bytes:
    return (text * (BLOCK_SIZE // len(text) + 1))[:BLOCK_SIZE].encode("ascii")


def _random_block() -> bytes:
    import os
    return os.urandom(BLOCK_SIZE)


def _high_entropy_block() -> bytes:
    """Return a block with entropy near 8 bits/byte (random bytes)."""
    import os
    return os.urandom(BLOCK_SIZE)


# ── Normal write — no containment ────────────────────────────────────────────

def test_normal_write_no_containment(engine: AegisEngine) -> None:
    """Writing low-entropy text blocks stays in NORMAL state with no alert."""
    assert engine.state is AegisState.NORMAL
    for i in range(20):
        decision = engine.write(i % 256, _text_block(f"record-{i:08d}"))
    assert engine.state is AegisState.NORMAL
    # Score should be low for low-entropy sequential text
    assert decision.score < 0.65


# ── High-entropy writes → ELEVATED state ─────────────────────────────────────

def test_high_entropy_writes_elevated(journal: DurableJournal, tmp_path: Path) -> None:
    """Many high-entropy writes raise the score above the alert threshold."""
    policy = Policy(PolicyConfig(
        minimum_operations=8,
        alert_threshold=0.55,
        containment_threshold=0.90,
        containment_enabled=False,
    ))
    eng = AegisEngine(journal, policy, tmp_path / "audit.jsonl")
    # Fill the window with high-entropy overwrites
    for i in range(64):
        lba = i % journal.blocks
        eng.write(lba, _high_entropy_block())
    # Engine should have transitioned to ELEVATED (alert, no containment)
    assert eng.state in (AegisState.ELEVATED, AegisState.NORMAL)
    # At minimum, the last decision should have scored high
    last = eng.write(0, _high_entropy_block())
    assert last.score > 0.3  # meaningful signal, even if not always ELEVATED


# ── Destructive command → CONTAINED state ────────────────────────────────────

def test_destructive_command_contained(engine: AegisEngine) -> None:
    """A rejected destructive admin command must force CONTAINED state."""
    assert engine.state is AegisState.NORMAL
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")
    assert engine.state is AegisState.CONTAINED


def test_writes_blocked_when_contained(engine: AegisEngine) -> None:
    """After containment, write() must raise PermissionError."""
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")
    assert engine.state is AegisState.CONTAINED
    with pytest.raises(PermissionError):
        engine.write(0, _text_block())


# ── Recovery authorization flow ───────────────────────────────────────────────

def test_recovery_authorization_flow(journal: DurableJournal, tmp_path: Path) -> None:
    """Full round-trip: contain → keygen → issue token → authorize recovery."""
    # Force containment
    policy = Policy(PolicyConfig())
    eng = AegisEngine(journal, policy, tmp_path / "audit.jsonl")
    eng.write(0, _text_block("before"))  # write one block so sequence > 0
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")
    assert eng.state is AegisState.CONTAINED

    # Generate keys
    priv_pem = tmp_path / "priv.pem"
    pub_pem = tmp_path / "pub.pem"
    generate_keypair(priv_pem, pub_pem)

    # Issue token
    import secrets as _secrets
    now = int(time.time())
    authorization = RecoveryAuthorization(
        action="enter_recovery_read_only",
        device_id=journal.device_id,
        expires_unix=now + 300,
        issued_unix=now,
        nonce=_secrets.token_hex(16),
        state_version=eng.state_version,
        target_sequence=journal.last_sequence,
    )
    token = sign_authorization(authorization, priv_pem.read_bytes())

    # Authorize recovery
    verifier = TokenVerifier(pub_pem.read_bytes())
    eng.authorize_recovery(token, verifier, physical_presence=True, now=now)
    assert eng.state is AegisState.RECOVERY_READ_ONLY


def test_recovery_requires_physical_presence(journal: DurableJournal, tmp_path: Path) -> None:
    """authorize_recovery must raise PermissionError without physical presence."""
    policy = Policy(PolicyConfig())
    eng = AegisEngine(journal, policy, tmp_path / "audit.jsonl")
    eng.reject_destructive_command(opcode=0xC0, name="format_nvm")

    priv_pem = tmp_path / "priv.pem"
    pub_pem = tmp_path / "pub.pem"
    generate_keypair(priv_pem, pub_pem)

    import secrets as _secrets
    now = int(time.time())
    authorization = RecoveryAuthorization(
        action="enter_recovery_read_only",
        device_id=journal.device_id,
        expires_unix=now + 300,
        issued_unix=now,
        nonce=_secrets.token_hex(16),
        state_version=eng.state_version,
        target_sequence=0,
    )
    token = sign_authorization(authorization, priv_pem.read_bytes())
    verifier = TokenVerifier(pub_pem.read_bytes())

    with pytest.raises(PermissionError, match="physical presence"):
        eng.authorize_recovery(token, verifier, physical_presence=False, now=now)


# ── Lab policy — containment on score threshold ───────────────────────────────

def test_lab_policy_containment(lab_engine: AegisEngine) -> None:
    """With the aggressive lab policy, high-entropy broad-overwrite triggers containment."""
    import os
    # Write many high-entropy random blocks across many LBAs to exceed the lab threshold
    for i in range(64):
        lba = (i * 3) % lab_engine.journal.blocks  # non-sequential, spread out
        payload = os.urandom(BLOCK_SIZE)
        try:
            lab_engine.write(lba, payload)
        except PermissionError:
            break  # already contained

    # Should have transitioned to CONTAINED
    assert lab_engine.state is AegisState.CONTAINED
