from __future__ import annotations

import math


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte, in the closed interval [0, 8]."""
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


def collision_concentration(data: bytes) -> int:
    """Exact sum(count(byte)^2), matching the streaming RTL proxy metric."""
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return sum(count * count for count in counts)
