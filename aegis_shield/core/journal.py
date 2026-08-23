from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import threading
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class JournalRecord:
    """A journal record with its payload materialised.

    Produced on demand by :meth:`DurableJournal.iter_records` and
    :meth:`DurableJournal.record_at`. Payloads are **not** held in memory —
    see :class:`_RecordIndex`.
    """

    sequence: int
    block: int
    data: bytes
    previous_hash: str
    record_hash: str


@dataclass(frozen=True, slots=True)
class _RecordIndex:
    """Where a record lives on disk, and what it covers.

    Holding payloads in memory made resident size grow without bound: every
    block ever written stayed resident forever, at ``block_size`` bytes each.
    A 64 GiB namespace rewritten once would need tens of gigabytes of RAM.

    This entry is ~100 bytes regardless of block size. Payloads are read back
    from ``journal.jsonl`` on demand and CRC-checked on the way out.
    """

    sequence: int
    block: int
    blocks: int
    offset: int          # byte offset of this record's line in journal.jsonl
    #: Stored as 32 raw bytes rather than a 64-character hex string; at one
    #: entry per write the difference is not academic. ``previous_hash`` is not
    #: stored at all — it is by definition the preceding entry's digest.
    record_digest: bytes

    @property
    def record_hash(self) -> str:
        return self.record_digest.hex()


class JournalCorruptionError(RuntimeError):
    pass


class DurableJournal:
    """File-backed, append-and-fsync reference journal.

    This deliberately favors inspectability and crash replay over throughput. It
    is not the production on-media format and never opens a raw block device.

    **Memory.** Payloads are not held in memory. The in-memory index stores a
    byte offset per record (~213 B measured, against 4096 B when payloads were
    resident — a 19x reduction), and the overlay maps each block to an index
    position rather than to its contents. A 64 GiB namespace rewritten once
    needs roughly 3.5 GB resident instead of 68 GB.

    That is a floor, not a fix for unbounded growth: the index still grows with
    the number of records, so a long-lived namespace should be compacted
    periodically (``compact()`` resets it). Removing the remaining per-record
    Python object would mean a packed binary index, which would cost the
    inspectability this class exists to provide.
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
        # block -> position in _index of the record that currently owns it.
        # Stores an index position, not the block's contents.
        self._overlay: dict[int, int] = {}
        self._index: list[_RecordIndex] = []
        self._last_hash = "0" * 64
        self._next_sequence = 1
        self._log_size = 0
        # One long-lived read handle; reopening per block made compaction do one
        # open() per block in the namespace. seek()+readline() is stateful, so
        # concurrent readers would interleave and hand each other the wrong
        # record. AegisEngine already serialises, but the journal is usable on
        # its own and must not be a footgun.
        self._log_reader = None
        self._reader_lock = threading.Lock()
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
        """Verify the chain and build the on-disk index.

        Reads with explicit ``readline()`` rather than iterating the handle:
        iteration buffers ahead, which makes ``tell()`` meaningless, and every
        record's byte offset has to be exact for reads to find it later.
        """
        expected_hash = "0" * 64
        expected_sequence = 1
        offset = 0
        with (self.root / self.LOG).open("rb") as handle:
            line_number = 0
            while True:
                raw = handle.readline()
                if not raw:
                    break
                line_offset = offset
                offset += len(raw)
                line_number += 1
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
                position = len(self._index)
                self._index.append(
                    _RecordIndex(
                        sequence=expected_sequence,
                        block=block,
                        blocks=blocks,
                        offset=line_offset,
                        record_digest=bytes.fromhex(stored_hash),
                    )
                )
                for block_offset in range(blocks):
                    self._overlay[block + block_offset] = position
                expected_hash = stored_hash
                expected_sequence += 1
        self._last_hash = expected_hash
        self._next_sequence = expected_sequence
        self._log_size = offset

    # ── payload access ───────────────────────────────────────────────────────

    def _reader(self):
        """Return the shared read handle, opening it if needed."""
        if self._log_reader is None or self._log_reader.closed:
            self._log_reader = (self.root / self.LOG).open("rb")
        return self._log_reader

    def _close_reader(self) -> None:
        lock = getattr(self, "_reader_lock", None)
        if lock is None:                      # partially constructed
            return
        with lock:
            if self._log_reader is not None and not self._log_reader.closed:
                self._log_reader.close()
            self._log_reader = None

    def _payload_at(self, position: int) -> bytes:
        """Read one record's payload back from disk.

        The CRC is re-checked here rather than trusted from replay time: the
        bytes are being handed to a caller now, and on-disk corruption after
        startup must not pass silently through a forensic read path.
        """
        entry = self._index[position]
        with self._reader_lock:
            handle = self._reader()
            handle.seek(entry.offset)
            raw = handle.readline()
        try:
            value = json.loads(raw)
            data = base64.b64decode(value["data_b64"], validate=True)
        except Exception as exc:
            raise JournalCorruptionError(
                f"journal record {entry.sequence} could not be read back"
            ) from exc
        if int(value["sequence"]) != entry.sequence:
            raise JournalCorruptionError(
                f"journal record {entry.sequence} is not at its indexed offset"
            )
        if zlib.crc32(data) != int(value["crc32"]):
            raise JournalCorruptionError(f"CRC mismatch reading record {entry.sequence}")
        if len(data) != entry.blocks * self.block_size:
            raise JournalCorruptionError(f"record {entry.sequence} has unexpected length")
        return data

    def _block_from(self, position: int, block: int) -> bytes:
        """Extract one block's content from the record that owns it."""
        entry = self._index[position]
        data = self._payload_at(position)
        start = (block - entry.block) * self.block_size
        return data[start : start + self.block_size]

    def record_at(self, position: int) -> JournalRecord:
        """Materialise a full record, payload included, by index position."""
        entry = self._index[position]
        return JournalRecord(
            sequence=entry.sequence,
            block=entry.block,
            data=self._payload_at(position),
            previous_hash=self.previous_hash_at(position),
            record_hash=entry.record_hash,
        )

    def previous_hash_at(self, position: int) -> str:
        """The hash this record chains from — the preceding record's digest."""
        if position == 0:
            return "0" * 64
        return self._index[position - 1].record_hash

    def _check_range(self, block: int, count: int) -> None:
        if block < 0 or count < 1 or block + count > self.blocks:
            raise ValueError("block range outside virtual namespace")

    @property
    def last_sequence(self) -> int:
        return self._next_sequence - 1

    def iter_records(self) -> Iterator[JournalRecord]:
        """Yield every record in sequence order, reading payloads on demand.

        A generator rather than a materialised tuple: the whole journal no
        longer fits in memory by construction, and callers stream it.
        """
        for position in range(len(self._index)):
            yield self.record_at(position)

    def read(self, block: int, count: int = 1, at_sequence: int | None = None) -> bytes:
        self._check_range(block, count)
        if at_sequence is not None and not 0 <= at_sequence <= self.last_sequence:
            raise ValueError("invalid sequence")
        result = bytearray()
        with (self.root / self.BASE).open("rb") as base:
            for current in range(block, block + count):
                data: bytes | None = None
                if at_sequence is None:
                    position = self._overlay.get(current)
                    if position is not None:
                        data = self._block_from(position, current)
                else:
                    # Point-in-time read: newest record at or before the target
                    # sequence that covers this block. Scanned in reverse so the
                    # first match is the newest.
                    for position in range(len(self._index) - 1, -1, -1):
                        entry = self._index[position]
                        if entry.sequence > at_sequence:
                            continue
                        if entry.block <= current < entry.block + entry.blocks:
                            data = self._block_from(position, current)
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
        serialized = _canonical(dict(body, record_hash=record_hash)) + b"\n"
        # The record's offset is the log size before this write. We are the only
        # writer, so the value stays exact.
        line_offset = self._log_size
        with (self.root / self.LOG).open("ab", buffering=0) as handle:
            handle.write(serialized)
            os.fsync(handle.fileno())
        self._log_size += len(serialized)

        position = len(self._index)
        self._index.append(
            _RecordIndex(
                sequence=self._next_sequence,
                block=start_block,
                blocks=count,
                offset=line_offset,
                record_digest=bytes.fromhex(record_hash),
            )
        )
        for block_offset in range(count):
            self._overlay[start_block + block_offset] = position
        sequence = self._next_sequence
        self._last_hash = record_hash
        self._next_sequence += 1
        return sequence

    def close(self) -> None:
        """Release the shared read handle. Safe to call more than once."""
        self._close_reader()

    def __enter__(self) -> "DurableJournal":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:  # best effort; close() is the supported path
        try:
            self._close_reader()
        except Exception:
            pass

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

    #: Blocks materialised per read during compaction. Bounds peak memory at
    #: ``COMPACT_CHUNK_BLOCKS * block_size`` while avoiding one file open per
    #: block — the previous behaviour meant 65,536 opens for a default namespace.
    COMPACT_CHUNK_BLOCKS = 256

    def compact(self, snapshot_name: str) -> None:
        """Create a retained snapshot, then atomically materialize the current logical image."""
        self.snapshot(snapshot_name)
        new_base = self.root / (self.BASE + ".new")
        with new_base.open("wb") as handle:
            for start in range(0, self.blocks, self.COMPACT_CHUNK_BLOCKS):
                count = min(self.COMPACT_CHUNK_BLOCKS, self.blocks - start)
                handle.write(self.read(start, count))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(new_base, self.root / self.BASE)
        self._fsync_directory(self.root)
        self._atomic_write(self.root / self.LOG, b"")
        # The log was replaced on disk; the shared read handle now points at a
        # file that no longer exists under that name.
        self._close_reader()
        self._overlay.clear()
        self._index.clear()
        self._last_hash = "0" * 64
        self._next_sequence = 1
        self._log_size = 0
