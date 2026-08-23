from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class JournalRecord:
    sequence: int
    block: int
    data: bytes
    previous_hash: str
    record_hash: str


class JournalCorruptionError(RuntimeError):
    pass


class DurableJournal:
    """File-backed, append-and-fsync reference journal.

    This deliberately favors inspectability and crash replay over throughput. It is not the
    production on-media format and never opens a raw block device.
    """

    METADATA = "metadata.json"
    BASE = "base.img"
    LOG = "journal.jsonl"

    @classmethod
    def provision(
        cls, root: str | Path, blocks: int, block_size: int = 4096, device_id: str | None = None
    ) -> "DurableJournal":
        if blocks < 1 or block_size < 512 or block_size & (block_size - 1):
            raise ValueError("blocks must be positive and block_size a power of two >= 512")
        path = Path(root)
        path.mkdir(parents=True, exist_ok=False)
        metadata = {
            "format": "aegis-reference-journal-v1",
            "device_id": device_id or str(uuid.uuid4()),
            "blocks": blocks,
            "block_size": block_size,
        }
        cls._atomic_write(path / cls.METADATA, _canonical(metadata) + b"\n")
        with (path / cls.BASE).open("wb") as handle:
            handle.truncate(blocks * block_size)
            handle.flush()
            os.fsync(handle.fileno())
        cls._atomic_write(path / cls.LOG, b"")
        cls._fsync_directory(path)
        return cls(path)

    def __init__(self, root: str | Path):
        self.root = Path(root)
        metadata = json.loads((self.root / self.METADATA).read_text(encoding="utf-8"))
        if metadata.get("format") != "aegis-reference-journal-v1":
            raise ValueError("unsupported journal format")
        self.device_id = str(metadata["device_id"])
        self.blocks = int(metadata["blocks"])
        self.block_size = int(metadata["block_size"])
        expected_size = self.blocks * self.block_size
        if (self.root / self.BASE).stat().st_size != expected_size:
            raise JournalCorruptionError("base image size does not match metadata")
        self._overlay: dict[int, tuple[int, bytes]] = {}
        self._records: list[JournalRecord] = []
        self._last_hash = "0" * 64
        self._next_sequence = 1
        self._replay()

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        temporary = path.with_suffix(path.suffix + ".new")
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        DurableJournal._fsync_directory(path.parent)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _replay(self) -> None:
        expected_hash = "0" * 64
        expected_sequence = 1
        with (self.root / self.LOG).open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw)
                    stored_hash = value.pop("record_hash")
                    calculated = hashlib.sha256(_canonical(value)).hexdigest()
                    data = base64.b64decode(value["data_b64"], validate=True)
                except Exception as exc:
                    raise JournalCorruptionError(f"invalid journal line {line_number}") from exc
                if stored_hash != calculated:
                    raise JournalCorruptionError(f"hash mismatch on line {line_number}")
                if value["previous_hash"] != expected_hash:
                    raise JournalCorruptionError(f"chain mismatch on line {line_number}")
                if int(value["sequence"]) != expected_sequence:
                    raise JournalCorruptionError(f"sequence mismatch on line {line_number}")
                if zlib.crc32(data) != int(value["crc32"]):
                    raise JournalCorruptionError(f"CRC mismatch on line {line_number}")
                blocks = int(value.get("blocks", 1))
                if blocks < 1 or len(data) != blocks * self.block_size:
                    raise JournalCorruptionError(f"record size mismatch on line {line_number}")
                block = int(value["block"])
                self._check_range(block, blocks)
                record = JournalRecord(expected_sequence, block, data, expected_hash, stored_hash)
                self._records.append(record)
                for offset in range(blocks):
                    chunk = data[offset * self.block_size : (offset + 1) * self.block_size]
                    self._overlay[block + offset] = (expected_sequence, chunk)
                expected_hash = stored_hash
                expected_sequence += 1
        self._last_hash = expected_hash
        self._next_sequence = expected_sequence

    def _check_range(self, block: int, count: int) -> None:
        if block < 0 or count < 1 or block + count > self.blocks:
            raise ValueError("block range outside virtual namespace")

    @property
    def last_sequence(self) -> int:
        return self._next_sequence - 1

    def iter_records(self) -> Iterator[JournalRecord]:
        return iter(tuple(self._records))

    def read(self, block: int, count: int = 1, at_sequence: int | None = None) -> bytes:
        self._check_range(block, count)
        if at_sequence is not None and not 0 <= at_sequence <= self.last_sequence:
            raise ValueError("invalid sequence")
        result = bytearray()
        with (self.root / self.BASE).open("rb") as base:
            for current in range(block, block + count):
                data: bytes | None = None
                if at_sequence is None:
                    overlay = self._overlay.get(current)
                    data = overlay[1] if overlay else None
                else:
                    for record in reversed(self._records):
                        record_blocks = len(record.data) // self.block_size
                        if (
                            record.sequence <= at_sequence
                            and record.block <= current < record.block + record_blocks
                        ):
                            offset = current - record.block
                            data = record.data[
                                offset * self.block_size : (offset + 1) * self.block_size
                            ]
                            break
                if data is None:
                    base.seek(current * self.block_size)
                    data = base.read(self.block_size)
                result.extend(data)
        return bytes(result)

    def append_block(self, block: int, data: bytes) -> int:
        if len(data) != self.block_size:
            raise ValueError("write must contain exactly one logical block")
        return self.append(block, data)

    def append(self, start_block: int, data: bytes) -> int:
        if not data or len(data) % self.block_size:
            raise ValueError("write must be a non-empty multiple of block_size")
        count = len(data) // self.block_size
        self._check_range(start_block, count)
        body = {
            "block": start_block,
            "blocks": count,
            "crc32": zlib.crc32(data),
            "data_b64": base64.b64encode(data).decode("ascii"),
            "previous_hash": self._last_hash,
            "sequence": self._next_sequence,
        }
        record_hash = hashlib.sha256(_canonical(body)).hexdigest()
        serialized = dict(body, record_hash=record_hash)
        with (self.root / self.LOG).open("ab", buffering=0) as handle:
            handle.write(_canonical(serialized) + b"\n")
            os.fsync(handle.fileno())
        record = JournalRecord(self._next_sequence, start_block, data, self._last_hash, record_hash)
        self._records.append(record)
        for offset in range(count):
            chunk = data[offset * self.block_size : (offset + 1) * self.block_size]
            self._overlay[start_block + offset] = (self._next_sequence, chunk)
        self._last_hash = record_hash
        self._next_sequence += 1
        return record.sequence

    def flush(self) -> None:
        for name in (self.LOG, self.BASE):
            with (self.root / name).open("rb") as handle:
                os.fsync(handle.fileno())

    _NAME_ALPHABET = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    )

    def snapshot(self, name: str, at_sequence: int | None = None) -> Path:
        """Copy the namespace into ``snapshots/<name>``.

        When *at_sequence* is given, the copied journal is truncated after that
        sequence so the bundle contains exactly the history it claims to.  The
        truncated log is re-verified by opening the snapshot, which fails loudly
        if the copy is not a valid, self-consistent chain.
        """
        if not name or any(character not in self._NAME_ALPHABET for character in name):
            raise ValueError(
                "snapshot name may contain only letters, digits, dash, and underscore"
            )
        if at_sequence is not None and not 0 <= at_sequence <= self.last_sequence:
            raise ValueError("invalid snapshot sequence")
        destination = self.root / "snapshots" / name
        destination.mkdir(parents=True, exist_ok=False)
        for source_name in (self.METADATA, self.BASE):
            shutil.copy2(self.root / source_name, destination / source_name)

        if at_sequence is None:
            shutil.copy2(self.root / self.LOG, destination / self.LOG)
        else:
            kept: list[bytes] = []
            with (self.root / self.LOG).open("rb") as handle:
                for raw in handle:
                    if not raw.strip():
                        continue
                    if int(json.loads(raw)["sequence"]) > at_sequence:
                        break
                    kept.append(raw if raw.endswith(b"\n") else raw + b"\n")
            self._atomic_write(destination / self.LOG, b"".join(kept))

        self._fsync_directory(destination)
        # Opening the copy replays and verifies its chain; a bad bundle raises.
        DurableJournal(destination)
        return destination

    def compact(self, snapshot_name: str) -> None:
        """Create a retained snapshot, then atomically materialize the current logical image."""
        self.snapshot(snapshot_name)
        new_base = self.root / (self.BASE + ".new")
        with new_base.open("wb") as handle:
            for block in range(self.blocks):
                handle.write(self.read(block))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(new_base, self.root / self.BASE)
        self._fsync_directory(self.root)
        self._atomic_write(self.root / self.LOG, b"")
        self._overlay.clear()
        self._records.clear()
        self._last_hash = "0" * 64
        self._next_sequence = 1
