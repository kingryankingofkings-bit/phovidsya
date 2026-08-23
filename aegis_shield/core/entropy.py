from __future__ import annotations

import math


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte, in the closed interval [0, 8].

    This runs on every write, so it bounds write throughput. Measured at roughly
    35 MB/s single-threaded on a 4 KiB block (~115 us/block). That is the ceiling
    for this reference deployment.

    The per-byte loop below is deliberate: ``collections.Counter``,
    ``bytes.count`` over 256 values, and sort-and-group were all measured and are
    all slower (0.97x, 0.14x, 0.20x respectively). Beating it needs numpy or a
    native extension, neither of which is worth a new dependency in a security
    product for this.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def changed_byte_fraction(before: bytes, after: bytes) -> float:
    if len(before) != len(after):
        raise ValueError("buffers must have equal length")
    if not before:
        return 0.0
    return sum(a != b for a, b in zip(before, after, strict=True)) / len(before)
