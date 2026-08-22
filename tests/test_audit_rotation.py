"""Tests for audit log size-based rotation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_shield.core.audit import AuditLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


def _archive_files(tmp_path: Path) -> list[Path]:
    return sorted(tmp_path.glob("audit.*.jsonl"))


# ---------------------------------------------------------------------------
# No-rotation baseline
# ---------------------------------------------------------------------------

def test_no_rotation_below_limit(tmp_path: Path) -> None:
    """Events below the size limit stay in the single log file."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=10_000)
    for i in range(5):
        log.append("test_event", {"i": i})

    assert not _archive_files(tmp_path), "no archive files should exist"
    events = _read_events(tmp_path / "audit.jsonl")
    assert len(events) == 5


def test_rotation_disabled_with_zero(tmp_path: Path) -> None:
    """max_bytes=0 completely disables rotation regardless of file size."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=0)
    for i in range(50):
        log.append("flood", {"i": i})

    assert not _archive_files(tmp_path)
    assert len(_read_events(path)) == 50


# ---------------------------------------------------------------------------
# Rotation mechanics
# ---------------------------------------------------------------------------

def test_rotation_creates_numbered_archive(tmp_path: Path) -> None:
    """When the size limit is reached, the old file is renamed to audit.1.jsonl."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)  # 1 byte → rotate on second append
    log.append("event_a")  # writes first entry; file now exceeds max_bytes
    log.append("event_b")  # size check fires → rotate before writing

    archives = _archive_files(tmp_path)
    assert len(archives) >= 1
    assert archives[0].name == "audit.1.jsonl"


def test_new_file_starts_with_boundary_event(tmp_path: Path) -> None:
    """After rotation, the active log's first entry is a rotation_boundary event."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log.append("event_a")
    log.append("event_b")

    events = _read_events(tmp_path / "audit.jsonl")
    assert events[0]["event"] == "rotation_boundary"
    assert "archived_to" in events[0]["details"]
    assert "previous_file_last_hash" in events[0]["details"]


def test_boundary_links_to_old_last_hash(tmp_path: Path) -> None:
    """The boundary event's previous_file_last_hash matches the archive's final entry hash."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log.append("event_a", {"v": 1})  # first entry; file now exceeds 1 byte
    log.append("event_b")            # triggers rotation before writing event_b

    archives = _archive_files(tmp_path)
    assert archives, "expected at least one archive"
    old_last_hash = _read_events(archives[0])[-1]["event_hash"]

    new_events = _read_events(tmp_path / "audit.jsonl")
    boundary = new_events[0]
    assert boundary["event"] == "rotation_boundary"
    assert boundary["details"]["previous_file_last_hash"] == old_last_hash


def test_triggering_event_follows_boundary(tmp_path: Path) -> None:
    """The event that caused rotation is written *after* the boundary entry."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log.append("event_a")        # fills old file → rotation → boundary written, then event_a in new file
    log.append("event_b")

    events = _read_events(tmp_path / "audit.jsonl")
    names = [e["event"] for e in events]
    assert names[0] == "rotation_boundary"
    assert "event_a" in names or "event_b" in names, "triggering event must appear after boundary"


# ---------------------------------------------------------------------------
# Chain integrity
# ---------------------------------------------------------------------------

def test_active_file_chain_is_valid_after_rotation(tmp_path: Path) -> None:
    """The active log's hash chain verifies cleanly after a rotation."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log.append("event_a")
    log.append("event_b")
    log.append("event_c")

    # verify() raises on any inconsistency
    log.verify()


def test_archive_file_chain_is_valid(tmp_path: Path) -> None:
    """The archived file's hash chain is self-consistent."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log.append("event_a")  # fills file beyond 1 byte
    log.append("event_b")  # triggers rotation; event_a file → audit.1.jsonl

    archives = _archive_files(tmp_path)
    assert archives
    archive_log = AuditLog(archives[0], max_bytes=0)  # open as read-only (no-rotation) log
    archive_log.verify()  # would raise ValueError on inconsistency


def test_multiple_rotations_produce_sequential_archives(tmp_path: Path) -> None:
    """Successive rotations yield audit.1.jsonl, audit.2.jsonl, …"""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    for i in range(6):
        log.append(f"event_{i}")

    archives = _archive_files(tmp_path)
    assert len(archives) >= 2
    for idx, archive in enumerate(archives, start=1):
        assert archive.name == f"audit.{idx}.jsonl"

    # Active log still verifies
    log.verify()


def test_reload_after_rotation_continues_chain(tmp_path: Path) -> None:
    """Re-opening the active log after rotation verifies and accepts new entries."""
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log.append("event_a")
    log.append("event_b")

    # Re-open with no rotation limit
    log2 = AuditLog(tmp_path / "audit.jsonl", max_bytes=0)
    log2.append("event_c")
    log2.verify()
