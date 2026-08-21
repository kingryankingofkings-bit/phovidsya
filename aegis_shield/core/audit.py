from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._last_hash = self.verify()

    def verify(self) -> str:
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
        body = {
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
