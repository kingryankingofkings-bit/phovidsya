"""Journal payload-offset indexing: correctness, integrity, and memory.

The journal used to hold every payload ever written in memory, plus a live copy
of every written block. This suite pins the replacement — an on-disk offset
index — against the properties that matter: identical reads, an intact hash
chain, corruption still detected, and bounded resident memory.
"""

from __future__ import annotations

import base64
import json
import os
import tracemalloc
from pathlib import Path

import pytest

from aegis_shield.core.journal import DurableJournal, JournalCorruptionError

BS = 4096


@pytest.fixture()
def journal(tmp_path: Path) -> DurableJournal:
    return DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BS)


def _payload(tag: str) -> bytes:
    return tag.encode().ljust(BS, b".")


# ---------------------------------------------------------------------------
# Reads must be byte-identical to what was written
# ---------------------------------------------------------------------------

def test_read_returns_what_was_written(journal: DurableJournal) -> None:
    journal.append(3, _payload("hello"))
    assert journal.read(3) == _payload("hello")


def test_latest_write_wins(journal: DurableJournal) -> None:
    journal.append(3, _payload("first"))
    journal.append(3, _payload("second"))
    assert journal.read(3) == _payload("second")


def test_unwritten_block_reads_from_base(journal: DurableJournal) -> None:
    assert journal.read(9) == bytes(BS)


def test_multiblock_write_reads_back_per_block(journal: DurableJournal) -> None:
    payload = _payload("a") + _payload("b") + _payload("c")
    journal.append(10, payload)
    assert journal.read(10) == _payload("a")
    assert journal.read(11) == _payload("b")
    assert journal.read(12) == _payload("c")
    assert journal.read(10, 3) == payload


def test_span_read_mixes_written_and_base(journal: DurableJournal) -> None:
    journal.append(1, _payload("one"))
    journal.append(3, _payload("three"))
    got = journal.read(0, 5)
    assert got[0:BS] == bytes(BS)
    assert got[BS : 2 * BS] == _payload("one")
    assert got[2 * BS : 3 * BS] == bytes(BS)
    assert got[3 * BS : 4 * BS] == _payload("three")


def test_random_workload_matches_a_reference_model(journal: DurableJournal) -> None:
    """Cross-check every block against an independent in-memory model."""
    import random

    rng = random.Random(7)
    model: dict[int, bytes] = {}
    for i in range(200):
        block = rng.randrange(64)
        payload = _payload(f"v{i}")
        journal.append(block, payload)
        model[block] = payload

    for block in range(64):
        assert journal.read(block) == model.get(block, bytes(BS)), f"block {block}"


# ---------------------------------------------------------------------------
# Point-in-time reads
# ---------------------------------------------------------------------------

def test_point_in_time_read_sees_the_older_value(journal: DurableJournal) -> None:
    first = journal.append(2, _payload("old"))
    journal.append(2, _payload("new"))
    assert journal.read(2, at_sequence=first) == _payload("old")
    assert journal.read(2) == _payload("new")


def test_point_in_time_read_before_any_write_sees_base(journal: DurableJournal) -> None:
    journal.append(2, _payload("later"))
    assert journal.read(2, at_sequence=0) == bytes(BS)


def test_point_in_time_read_rejects_future_sequence(journal: DurableJournal) -> None:
    journal.append(2, _payload("x"))
    with pytest.raises(ValueError):
        journal.read(2, at_sequence=99)


# ---------------------------------------------------------------------------
# Records and the hash chain
# ---------------------------------------------------------------------------

def test_iter_records_yields_payloads_in_order(journal: DurableJournal) -> None:
    for i in range(5):
        journal.append(i, _payload(f"r{i}"))
    records = list(journal.iter_records())
    assert [r.sequence for r in records] == [1, 2, 3, 4, 5]
    assert [r.data for r in records] == [_payload(f"r{i}") for i in range(5)]


def test_chain_links_are_reconstructed_correctly(journal: DurableJournal) -> None:
    """previous_hash is derived, not stored — it must still be right."""
    for i in range(6):
        journal.append(i, _payload(f"c{i}"))
    records = list(journal.iter_records())
    assert records[0].previous_hash == "0" * 64
    for earlier, later in zip(records, records[1:]):
        assert later.previous_hash == earlier.record_hash


def test_record_at_matches_iter_records(journal: DurableJournal) -> None:
    for i in range(4):
        journal.append(i, _payload(f"m{i}"))
    assert [journal.record_at(i) for i in range(4)] == list(journal.iter_records())


# ---------------------------------------------------------------------------
# Durability and reopen
# ---------------------------------------------------------------------------

def test_reopen_reads_identically(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    original = DurableJournal.provision(root, blocks=32, block_size=BS)
    for i in range(20):
        original.append(i % 32, _payload(f"d{i}"))
    snapshot = [original.read(b) for b in range(32)]
    original.close()

    reopened = DurableJournal(root)
    assert [reopened.read(b) for b in range(32)] == snapshot
    assert reopened.last_sequence == 20


def test_append_after_reopen_continues_the_chain(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    first = DurableJournal.provision(root, blocks=16, block_size=BS)
    first.append(0, _payload("before"))
    first.close()

    second = DurableJournal(root)
    second.append(1, _payload("after"))
    records = list(second.iter_records())
    assert records[1].previous_hash == records[0].record_hash
    assert second.read(0) == _payload("before")
    assert second.read(1) == _payload("after")


# ---------------------------------------------------------------------------
# Corruption must still be caught — offsets must not weaken integrity
# ---------------------------------------------------------------------------

def test_truncated_tail_recovers_rather_than_bricking(tmp_path: Path) -> None:
    """A torn final record is discarded — see tests/test_crash_recovery.py.

    This once asserted that truncation raised. It does not any more: refusing
    to open would make an ordinary power cut permanently unrecoverable, and the
    torn record was never acknowledged to any caller.
    """
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    for i in range(4):
        j.append(i, _payload(f"t{i}"))
    j.close()

    log = root / "journal.jsonl"
    log.write_bytes(log.read_bytes()[:-40])  # tear the final record

    reopened = DurableJournal(root)
    assert reopened.last_sequence == 3
    assert reopened.recovered_tail is not None


def test_truncation_in_the_middle_is_still_detected(tmp_path: Path) -> None:
    """Only the tail is forgiven. Damage with records after it is corruption."""
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    for i in range(4):
        j.append(i, _payload(f"t{i}"))
    j.close()

    log = root / "journal.jsonl"
    lines = log.read_bytes().splitlines(True)
    lines[1] = lines[1][:-40] + b"\n"
    log.write_bytes(b"".join(lines))

    with pytest.raises(JournalCorruptionError):
        DurableJournal(root)


def test_tampered_payload_is_detected_on_replay(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    j.append(0, _payload("original"))
    j.close()

    log = root / "journal.jsonl"
    entry = json.loads(log.read_bytes())
    entry["data_b64"] = base64.b64encode(_payload("tampered")).decode()
    log.write_bytes(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    with pytest.raises(JournalCorruptionError):
        DurableJournal(root)


def test_payload_corrupted_after_startup_is_caught_on_read(tmp_path: Path) -> None:
    """Payloads are read from disk lazily, so they must be re-checked then.

    Verifying only at replay would let corruption that happens while the daemon
    is running pass silently into a forensic read.
    """
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    j.append(0, _payload("trustworthy"))

    log = root / "journal.jsonl"
    entry = json.loads(log.read_bytes())
    entry["data_b64"] = base64.b64encode(_payload("swapped")).decode()
    log.write_bytes(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    with pytest.raises(JournalCorruptionError):
        j.read(0)


# ---------------------------------------------------------------------------
# Compaction
# ---------------------------------------------------------------------------

def test_compaction_preserves_the_logical_image(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=300, block_size=BS)  # > chunk size
    for i in range(0, 300, 3):
        j.append(i, _payload(f"k{i}"))
    before = [j.read(b) for b in range(300)]

    j.compact("snap")
    assert [j.read(b) for b in range(300)] == before
    assert j.last_sequence == 0
    assert (root / "snapshots" / "snap").exists()


def test_writes_work_after_compaction(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    j.append(0, _payload("pre"))
    j.compact("snap")
    j.append(1, _payload("post"))

    assert j.read(0) == _payload("pre")     # from the new base image
    assert j.read(1) == _payload("post")    # from the fresh journal
    assert list(j.iter_records())[0].previous_hash == "0" * 64


def test_reopen_after_compaction(tmp_path: Path) -> None:
    root = tmp_path / "ns"
    j = DurableJournal.provision(root, blocks=16, block_size=BS)
    j.append(0, _payload("kept"))
    j.compact("snap")
    j.close()

    assert DurableJournal(root).read(0) == _payload("kept")


# ---------------------------------------------------------------------------
# Memory — the reason for the change
# ---------------------------------------------------------------------------

def test_resident_memory_does_not_scale_with_payload_size(tmp_path: Path) -> None:
    """Per-write cost must be far below one block, or large volumes are impossible."""
    j = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BS)
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        writes = 400
        for i in range(writes):
            j.append(i % 64, os.urandom(BS))
        per_write = (tracemalloc.get_traced_memory()[0] - base) / writes
    finally:
        tracemalloc.stop()

    assert per_write < BS / 4, (
        f"{per_write:.0f} B/write against a {BS} B block — payloads look resident again"
    )


def test_overlay_is_bounded_by_namespace_size(tmp_path: Path) -> None:
    j = DurableJournal.provision(tmp_path / "ns", blocks=32, block_size=BS)
    for i in range(500):
        j.append(i % 32, _payload(f"o{i}"))
    assert len(j._overlay) <= 32


def test_index_entry_is_small(tmp_path: Path) -> None:
    """No payload, no stored previous_hash, slotted."""
    j = DurableJournal.provision(tmp_path / "ns", blocks=8, block_size=BS)
    j.append(0, _payload("x"))
    entry = j._index[0]
    assert not hasattr(entry, "__dict__"), "slots=True keeps entries compact"
    assert not hasattr(entry, "data")
    assert len(entry.record_digest) == 32


# ---------------------------------------------------------------------------
# Handle hygiene
# ---------------------------------------------------------------------------

def test_close_is_idempotent(journal: DurableJournal) -> None:
    journal.append(0, _payload("x"))
    journal.close()
    journal.close()
    assert journal.read(0) == _payload("x")  # reopens on demand


def test_context_manager_closes(tmp_path: Path) -> None:
    with DurableJournal.provision(tmp_path / "ns", blocks=8, block_size=BS) as j:
        j.append(0, _payload("x"))
        assert j.read(0) == _payload("x")
    assert j._log_reader is None


def test_concurrent_reads_do_not_interleave(tmp_path: Path) -> None:
    """The shared read handle is stateful; concurrent seeks must not cross."""
    import threading

    j = DurableJournal.provision(tmp_path / "ns", blocks=64, block_size=BS)
    for block in range(64):
        j.append(block, _payload(f"block-{block:03d}"))

    errors: list[str] = []

    def reader(block: int) -> None:
        want = _payload(f"block-{block:03d}")
        for _ in range(40):
            if j.read(block) != want:
                errors.append(f"block {block} read the wrong record")
                return

    threads = [threading.Thread(target=reader, args=(b,)) for b in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
