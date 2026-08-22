from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLog:
    """Append-only, hash-chained audit log with optional size-based rotation.

    Each entry includes a SHA-256 hash of the previous entry, forming a tamper-evident
    chain.  When the active log file reaches *max_bytes*, it is archived (renamed to
    ``<stem>.<n><suffix>``) and a fresh log is started.  The first entry of every new
    file is a ``rotation_boundary`` event whose ``details`` carry:

    * ``archived_to`` — filename of the archived file.
    * ``previous_file_last_hash`` — the ``event_hash`` of the final entry in that file,
      allowing an auditor to reconstruct the full cross-file chain.

    Set *max_bytes* to ``0`` to disable rotation entirely.
    """

    def __init__(self, path: str | Path, max_bytes: int = _DEFAULT_MAX_BYTES):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._last_hash = self.verify()

    # ── Internals ──────────────────────────────────────────────────────────────────────

    def _next_archive_path(self) -> Path:
        """Return the next available numbered archive path (e.g. ``audit.1.jsonl``)."""
        stem = self.path.stem
        suffix = self.path.suffix
        parent = self.path.parent
        i = 1
        while True:
            candidate = parent / f"{stem}.{i}{suffix}"
            if not candidate.exists():
                return candidate
            i += 1

    def _rotate(self) -> None:
        """Archive the current log file and start a fresh one.

        Writes a ``rotation_boundary`` event as the first entry of the new file.
        The boundary event's ``details`` link back to the archived file so the
        full chain can be reconstructed by an auditor.
        """
        archive = self._next_archive_path()
        old_hash = self._last_hash
        self.path.rename(archive)
        self.path.touch()
        # The new file's chain starts fresh; boundary event is entry 0.
        self._last_hash = "0" * 64
        boundary_body: dict[str, Any] = {
            "details": {
                "archived_to": archive.name,
                "previous_file_last_hash": old_hash,
            },
            "event": "rotation_boundary",
            "previous_hash": self._last_hash,
            "timestamp_ns": time.time_ns(),
        }
        boundary_hash = hashlib.sha256(_canonical(boundary_body)).hexdigest()
        with self.path.open("ab", buffering=0) as handle:
            handle.write(_canonical(dict(boundary_body, event_hash=boundary_hash)) + b"\n")
            os.fsync(handle.fileno())
        self._last_hash = boundary_hash

    # ── Public API ─────────────────────────────────────────────────────────────────────

    def verify(self) -> str:
        """Walk the active log, verifying every hash link.

        Returns the ``event_hash`` of the last entry (or ``"0" * 64`` for an empty
        file), and raises :class:`ValueError` on the first inconsistency found.
        """
        expected = "0" * 64
        with self.path.open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                value = json.loads(raw)
                stored = value.pop("event_hash")
                if value.get("previous_hash") != expected:
                    raise ValueError(f"audit chain mismatch at line {line_number}")
                calculated = hashlib.sha256(_canonical(value)).hexdigest()
                if stored != calculated:
                    raise ValueError(f"audit hash mismatch at line {line_number}")
                expected = stored
        return expected

    def append(self, event: str, details: dict[str, Any] | None = None) -> str:
        """Append a signed event, rotating first if the size limit has been reached.

        Returns the ``event_hash`` of the new entry.
        """
        if self.max_bytes > 0 and self.path.stat().st_size >= self.max_bytes:
            self._rotate()

        body: dict[str, Any] = {
            "details": details or {},
            "event": event,
            "previous_hash": self._last_hash,
            "timestamp_ns": time.time_ns(),
        }
        event_hash = hashlib.sha256(_canonical(body)).hexdigest()
        with self.path.open("ab", buffering=0) as handle:
            handle.write(_canonical(dict(body, event_hash=event_hash)) + b"\n")
            os.fsync(handle.fileno())
        self._last_hash = event_hash
        return event_hash
