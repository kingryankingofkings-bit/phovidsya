"""Crash recovery: an unacknowledged partial record must not brick the namespace.

A crash between write() and fsync() — an ordinary power cut — leaves a partial
record at the end of the journal. That record was never acknowledged, so
discarding it loses nothing any caller believes is durable. Refusing to open
would make a power loss indistinguishable from an attack on the evidence, and
would leave the device permanently unrecoverable.

The allowance is strictly limited to the FINAL record. Anything earlier is
genuine corruption and must still refuse to open.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.journal import JournalCorruptionError

BS = 4096


def _payload(tag: str) -> bytes:
    return tag.encode().ljust(BS, b".")


def _journal_with(root: Path, count: int = 3) -> Path:
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    for i in range(count):
        j.append(i, _payload(f"rec{i}"))
    j.close()
    return root / "journal.jsonl"


def _audit_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Torn tail — must recover
# ---------------------------------------------------------------------------

def test_torn_final_record_is_discarded(tmp_path: Path) -> None:
    log = _journal_with(tmp_path / "ns")
    log.write_bytes(log.read_bytes()[:-70])

    j = DurableJournal(tmp_path / "ns")
    assert j.last_sequence == 2
    assert j.recovered_tail is not None


def test_partial_line_without_newline_is_discarded(tmp_path: Path) -> None:
    """The classic torn write: bytes stop mid-record with no terminator."""
    log = _journal_with(tmp_path / "ns")
    log.write_bytes(log.read_bytes() + b'{"block":9,"blocks":1,"crc32"')

    j = DurableJournal(tmp_path / "ns")
    assert j.last_sequence == 3
    assert j.recovered_tail is not None


def test_surviving_records_still_read_correctly(tmp_path: Path) -> None:
    log = _journal_with(tmp_path / "ns")
    log.write_bytes(log.read_bytes()[:-70])

    j = DurableJournal(tmp_path / "ns")
    assert j.read(0) == _payload("rec0")
    assert j.read(1) == _payload("rec1")
    assert j.read(2) == bytes(BS), "the discarded record must not be visible"


def test_appends_continue_after_recovery(tmp_path: Path) -> None:
    """The log must be truncated, or the next append would follow torn bytes."""
    log = _journal_with(tmp_path / "ns")
    log.write_bytes(log.read_bytes()[:-70])

    j = DurableJournal(tmp_path / "ns")
    j.append(7, _payload("after"))
    assert j.read(7) == _payload("after")

    records = list(j.iter_records())
    assert [r.sequence for r in records] == [1, 2, 3]
    for earlier, later in zip(records, records[1:]):
        assert later.previous_hash == earlier.record_hash


def test_recovered_journal_reopens_cleanly(tmp_path: Path) -> None:
    log = _journal_with(tmp_path / "ns")
    log.write_bytes(log.read_bytes()[:-70])

    DurableJournal(tmp_path / "ns").close()
    again = DurableJournal(tmp_path / "ns")
    assert again.recovered_tail is None, "recovery must not repeat on a clean log"
    assert again.last_sequence == 2


def test_torn_bytes_are_preserved_not_destroyed(tmp_path: Path) -> None:
    """A forensic product must not silently delete data, even invalid data."""
    root = tmp_path / "ns"
    log = _journal_with(root)
    log.write_bytes(log.read_bytes()[:-70])

    truncated = log.read_bytes()          # what remained after the simulated crash
    j = DurableJournal(root)

    sidecars = list(root.glob("journal.jsonl.torn-*"))
    assert len(sidecars) == 1
    assert sidecars[0].name == j.recovered_tail.sidecar
    # The sidecar holds exactly the bytes removed from the live log.
    assert sidecars[0].read_bytes() == truncated[j._log_size :]
    assert sidecars[0].stat().st_size == j.recovered_tail.bytes_discarded
    assert log.read_bytes() == truncated[: j._log_size]


def test_only_one_record_is_ever_discarded(tmp_path: Path) -> None:
    """Truncation stops at the torn record; earlier records are untouched."""
    root = tmp_path / "ns"
    log = _journal_with(root, count=5)
    log.write_bytes(log.read_bytes()[:-70])

    j = DurableJournal(root)
    assert j.last_sequence == 4
    assert len(list(j.iter_records())) == 4


def test_torn_first_and_only_record(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    log = _journal_with(root, count=1)
    log.write_bytes(log.read_bytes()[:-70])

    j = DurableJournal(root)
    assert j.last_sequence == 0
    assert j.read(0) == bytes(BS)
    j.append(0, _payload("fresh"))
    assert list(j.iter_records())[0].previous_hash == "0" * 64


# ---------------------------------------------------------------------------
# Corruption before the tail — must still refuse
# ---------------------------------------------------------------------------

def test_corrupt_middle_record_still_refuses_to_open(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    log = _journal_with(root, count=4)
    lines = log.read_bytes().splitlines(True)
    lines[1] = lines[1][:-30] + b"\n"
    log.write_bytes(b"".join(lines))

    with pytest.raises(JournalCorruptionError):
        DurableJournal(root)


def test_tampered_middle_payload_still_refuses(tmp_path: Path) -> None:
    """A later record proves the earlier one was complete when written."""
    root = tmp_path / "ns"
    log = _journal_with(root, count=3)
    lines = log.read_bytes().splitlines(True)
    entry = json.loads(lines[0])
    entry["data_b64"] = base64.b64encode(_payload("tampered")).decode()
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    log.write_bytes(b"".join(lines))

    with pytest.raises(JournalCorruptionError):
        DurableJournal(root)


def test_broken_chain_in_the_middle_still_refuses(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    log = _journal_with(root, count=4)
    lines = log.read_bytes().splitlines(True)
    log.write_bytes(lines[0] + lines[2] + lines[3])  # drop record 2

    with pytest.raises(JournalCorruptionError):
        DurableJournal(root)


def test_tampered_final_payload_is_not_treated_as_a_torn_tail(tmp_path: Path) -> None:
    """A well-formed final record that fails its CRC is corruption, not a tear.

    A torn write truncates; it does not produce a complete, parseable record
    whose checksum happens to be wrong. Discarding this case would let an
    attacker delete the newest evidence by flipping bits in it.
    """
    root = tmp_path / "ns"
    log = _journal_with(root, count=3)
    lines = log.read_bytes().splitlines(True)
    entry = json.loads(lines[-1])
    entry["data_b64"] = base64.b64encode(_payload("swapped")).decode()
    lines[-1] = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    log.write_bytes(b"".join(lines))

    with pytest.raises(JournalCorruptionError):
        DurableJournal(root)


# ---------------------------------------------------------------------------
# The engine must record the recovery
# ---------------------------------------------------------------------------

def test_engine_audits_the_recovery(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    audit = tmp_path / "audit.jsonl"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    engine = AegisEngine(j, Policy(PolicyConfig()), audit)
    for i in range(3):
        engine.write(i, _payload(f"e{i}"))
    j.close()

    log = root / "journal.jsonl"
    log.write_bytes(log.read_bytes()[:-70])

    AegisEngine(DurableJournal(root), Policy(PolicyConfig()), audit)
    recovered = [e for e in _audit_events(audit) if e["event"] == "journal_tail_recovered"]
    assert recovered, "discarding data must never be silent"
    details = recovered[-1]["details"]
    assert details["bytes_discarded"] > 0
    assert details["preserved_as"].startswith("journal.jsonl.torn-")


def test_clean_open_records_no_recovery(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    audit = tmp_path / "audit.jsonl"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    engine = AegisEngine(j, Policy(PolicyConfig()), audit)
    engine.write(0, _payload("clean"))
    j.close()

    AegisEngine(DurableJournal(root), Policy(PolicyConfig()), audit)
    assert not [e for e in _audit_events(audit) if e["event"] == "journal_tail_recovered"]


def test_device_remains_usable_after_a_power_cut(tmp_path: Path) -> None:
    """The whole point: a power cut must not brick the namespace."""
    root = tmp_path / "ns"
    audit = tmp_path / "audit.jsonl"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    engine = AegisEngine(j, Policy(PolicyConfig()), audit)
    for i in range(3):
        engine.write(i, _payload(f"p{i}"))
    j.close()

    log = root / "journal.jsonl"
    log.write_bytes(log.read_bytes()[:-70])

    recovered = AegisEngine(DurableJournal(root), Policy(PolicyConfig()), audit)
    assert recovered.status()["writes_allowed"] is True
    assert recovered.read(0) == _payload("p0")
    recovered.write(9, _payload("post-recovery"))
    assert recovered.read(9) == _payload("post-recovery")
