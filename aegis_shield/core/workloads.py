"""Synthetic I/O workloads for measuring policy behaviour.

**These are models of I/O shape, not captures of real software and not real
malware.** They exist so the policy thresholds can be measured against
*something* rather than asserted — see ``docs/DETECTION.md`` for exactly what
this can and cannot establish.

The benign set deliberately includes the workloads that are hardest for an
entropy-based detector: copying compressed archives and media files produces
byte streams statistically indistinguishable from encryption. A detector that
cannot separate "writing a tarball" from "encrypting the disk" is not usable,
and entropy alone cannot make that distinction. The separating signals are
*read-before-write*, *overwrite of existing content*, and *breadth of coverage*
— ransomware reads what is there and replaces it in place, across the namespace.
"""

from __future__ import annotations

import random
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .types import IoEvent, IoKind


@dataclass(frozen=True)
class Workload:
    """A named, deterministic I/O pattern."""

    name: str
    kind: str                      # "benign" or "ransomware"
    description: str
    generate: Callable[[int, int, int], Iterator[IoEvent]] = field(repr=False)
    #                  blocks, block_size, seed


# ── payload shapes ───────────────────────────────────────────────────────────


def _incompressible(rng: random.Random, size: int) -> bytes:
    """Bytes with ~8.0 bits/byte entropy — what encryption *and* compression look like."""
    return rng.randbytes(size)


def _compressed_archive(rng: random.Random, size: int) -> bytes:
    """A real deflate stream. Genuinely high entropy, genuinely benign."""
    source = bytes(rng.choice(b"the quick brown fox jumps over a lazy dog 0123456789 ")
                   for _ in range(size * 2))
    blob = zlib.compress(source, level=9)
    while len(blob) < size:
        blob += zlib.compress(source[:: rng.randint(1, 3)], level=9)
    return blob[:size]


def _jpeg_like(rng: random.Random, size: int) -> bytes:
    """Media: a small structured header then incompressible entropy-coded data."""
    header = bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b"\x00\x10JFIF\x00\x01\x01\x01"
    return (header + rng.randbytes(size))[:size]


def _text(rng: random.Random, size: int, tag: str = "record") -> bytes:
    """Log/document content: ~4-5 bits/byte."""
    words = b"alpha beta gamma delta epsilon zeta eta theta iota kappa ".split()
    out = bytearray()
    while len(out) < size:
        out += b" ".join(rng.choice(words) for _ in range(12))
        out += f" [{tag}-{rng.randrange(10**6):06d}]\n".encode()
    return bytes(out[:size])


def _sparse_binary(rng: random.Random, size: int) -> bytes:
    """Database page: structured header, mostly zeros, some packed values."""
    page = bytearray(size)
    page[0:8] = (rng.randrange(2**32)).to_bytes(8, "little")
    for _ in range(size // 64):
        offset = rng.randrange(16, size - 8)
        page[offset : offset + 8] = rng.randrange(2**48).to_bytes(8, "little")
    return bytes(page)


# ── benign workloads ─────────────────────────────────────────────────────────


def _archive_copy(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Copying a large .tar.gz onto the volume. Maximum entropy, zero malice.

    The hardest benign case: byte-for-byte indistinguishable from encryption at
    the payload level. Only the access *pattern* separates it — sequential
    writes to fresh blocks, no reads of what was there, no overwrites.
    """
    rng = random.Random(seed)
    for i in range(120):
        yield IoEvent(IoKind.WRITE, i % blocks, 1, _compressed_archive(rng, block_size), 0)


def _media_import(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Importing photos/video. High entropy, sequential, fresh blocks."""
    rng = random.Random(seed)
    for i in range(120):
        yield IoEvent(IoKind.WRITE, i % blocks, 1, _jpeg_like(rng, block_size), 0)


def _encrypted_volume_fill(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Writing into an encrypted-at-rest store (LUKS, encrypted DB).

    Every write is maximum entropy by design. This is the workload most likely
    to be misread as an attack.
    """
    rng = random.Random(seed)
    for i in range(120):
        yield IoEvent(IoKind.WRITE, i % blocks, 1, _incompressible(rng, block_size), 0)


def _database_oltp(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Transactional database: random-access page reads and rewrites.

    High overwrite and high read-before-write — but low entropy. Tests that the
    detector does not fire on overwrite patterns alone.
    """
    rng = random.Random(seed)
    hot = [rng.randrange(blocks) for _ in range(max(4, blocks // 12))]
    for _ in range(120):
        page = rng.choice(hot)
        yield IoEvent(IoKind.READ, page, 1, b"", 0)
        yield IoEvent(IoKind.WRITE, page, 1, _sparse_binary(rng, block_size), 0)


def _log_append(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Append-only logging. Sequential, low entropy, fresh blocks."""
    rng = random.Random(seed)
    for i in range(120):
        yield IoEvent(IoKind.WRITE, i % blocks, 1, _text(rng, block_size, "log"), 0)


def _software_update(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Package upgrade: reads then replaces many existing files.

    Structurally the closest benign analogue to ransomware — read-before-write,
    overwrite, broad coverage — but the replacement content is real binaries and
    text, not ciphertext. Entropy is what must separate this case.
    """
    rng = random.Random(seed)
    for i in range(120):
        target = (i * 3) % blocks
        yield IoEvent(IoKind.READ, target, 1, b"", 0)
        payload = _sparse_binary(rng, block_size) if i % 3 else _text(rng, block_size, "bin")
        yield IoEvent(IoKind.WRITE, target, 1, payload, 0)


def _backup_restore(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Restoring a backup: broad coverage, sequential, mixed content, overwrites."""
    rng = random.Random(seed)
    for i in range(150):
        target = i % blocks
        payload = _compressed_archive(rng, block_size) if i % 4 == 0 else _text(rng, block_size)
        yield IoEvent(IoKind.WRITE, target, 1, payload, 0)


# ── ransomware-shaped workloads ──────────────────────────────────────────────


def _encrypt_in_place(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """The canonical pattern: read a file, write ciphertext over it, move on.

    Every discriminating signal at once — read-before-write, overwrite, maximum
    entropy, broad coverage.
    """
    rng = random.Random(seed)
    for i in range(120):
        target = (i * 7) % blocks
        yield IoEvent(IoKind.READ, target, 1, b"", 0)
        yield IoEvent(IoKind.WRITE, target, 1, _incompressible(rng, block_size), 0)


def _encrypt_and_wipe(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Encrypt in place, then issue discards to defeat undelete."""
    rng = random.Random(seed)
    for i in range(120):
        target = (i * 11) % blocks
        yield IoEvent(IoKind.READ, target, 1, b"", 0)
        yield IoEvent(IoKind.WRITE, target, 1, _incompressible(rng, block_size), 0)
        if i % 4 == 0:
            yield IoEvent(IoKind.DEALLOCATE, target, 1, b"", 0)


def _low_and_slow(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Evasive: encryption interleaved with benign traffic to dilute the window.

    The hardest detection case. Included so the measurement is honest about
    where the detector is weak, not only where it is strong.
    """
    rng = random.Random(seed)
    for i in range(200):
        if i % 3 == 0:
            target = (i * 5) % blocks
            yield IoEvent(IoKind.READ, target, 1, b"", 0)
            yield IoEvent(IoKind.WRITE, target, 1, _incompressible(rng, block_size), 0)
        else:
            yield IoEvent(IoKind.WRITE, i % blocks, 1, _text(rng, block_size), 0)


def _minimal_evasion(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """The cheapest evasion that works: one benign write per encryption.

    Not an exotic attack — a single interleaved write is enough to drop the
    windowed mean below the containment threshold. Included because it bounds
    how much evasion effort the current design actually demands, which is
    almost none. See ``docs/DETECTION.md``.
    """
    rng = random.Random(seed)
    for i in range(240):
        target = (i * 7) % blocks
        yield IoEvent(IoKind.READ, target, 1, b"", 0)
        yield IoEvent(IoKind.WRITE, target, 1, _incompressible(rng, block_size), 0)
        yield IoEvent(IoKind.WRITE, (target + 1) % blocks, 1, _text(rng, block_size), 0)


def _targeted_documents(blocks: int, block_size: int, seed: int) -> Iterator[IoEvent]:
    """Encrypt only a subset — documents, not the whole namespace.

    Narrow coverage, so the coverage signal contributes little. Tests whether
    the remaining signals still carry the decision.
    """
    rng = random.Random(seed)
    region = max(8, blocks // 8)
    for i in range(120):
        target = i % region
        yield IoEvent(IoKind.READ, target, 1, b"", 0)
        yield IoEvent(IoKind.WRITE, target, 1, _incompressible(rng, block_size), 0)


BENIGN: tuple[Workload, ...] = (
    Workload("archive_copy", "benign",
             "Copying a compressed archive (maximum entropy, fresh blocks)", _archive_copy),
    Workload("media_import", "benign",
             "Importing photos/video (high entropy, sequential)", _media_import),
    Workload("encrypted_volume_fill", "benign",
             "Writing into an encrypted-at-rest store (entropy by design)",
             _encrypted_volume_fill),
    Workload("database_oltp", "benign",
             "Transactional DB: random page read-modify-write", _database_oltp),
    Workload("log_append", "benign",
             "Append-only logging (low entropy, sequential)", _log_append),
    Workload("software_update", "benign",
             "Package upgrade: read and replace many files", _software_update),
    Workload("backup_restore", "benign",
             "Restoring a backup across the namespace", _backup_restore),
)

RANSOMWARE: tuple[Workload, ...] = (
    Workload("encrypt_in_place", "ransomware",
             "Read, encrypt, overwrite across the namespace", _encrypt_in_place),
    Workload("encrypt_and_wipe", "ransomware",
             "Encrypt in place then discard to defeat recovery", _encrypt_and_wipe),
    Workload("low_and_slow", "ransomware",
             "Encryption diluted with benign traffic (evasive)", _low_and_slow),
    Workload("targeted_documents", "ransomware",
             "Encrypt a narrow document region only", _targeted_documents),
    Workload("minimal_evasion", "ransomware",
             "One benign write per encryption — the cheapest evasion that works",
             _minimal_evasion),
)

ALL: tuple[Workload, ...] = BENIGN + RANSOMWARE
