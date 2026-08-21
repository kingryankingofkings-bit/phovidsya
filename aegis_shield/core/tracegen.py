from __future__ import annotations

import base64
import json
import random
from pathlib import Path


def synthetic_trace(pattern: str, *, blocks: int, block_size: int, operations: int, seed: int = 1) -> list[dict]:
    """Generate non-malware I/O traces for control-path testing only."""
    if pattern not in {"sequential_text", "high_entropy_append", "broad_overwrite", "low_and_slow"}:
        raise ValueError("unknown synthetic pattern")
    rng = random.Random(seed)
    events: list[dict] = []
    for index in range(operations):
        if pattern == "sequential_text":
            lba = index % blocks
            payload = ((f"record-{index:08d}|" * ((block_size // 16) + 1)).encode())[:block_size]
        elif pattern == "high_entropy_append":
            lba = index % blocks
            payload = rng.randbytes(block_size)
        elif pattern == "broad_overwrite":
            lba = (index * 7919) % blocks
            payload = rng.randbytes(block_size)
            events.append({"kind": "read", "lba": lba, "blocks": 1})
        else:
            lba = (index * max(1, blocks // max(1, operations))) % blocks
            payload = rng.randbytes(block_size) if index % 4 == 0 else bytes([index % 251]) * block_size
        events.append(
            {
                "kind": "write",
                "lba": lba,
                "blocks": 1,
                "payload_b64": base64.b64encode(payload).decode("ascii"),
            }
        )
    return events


def write_trace(path: str | Path, events: list[dict]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
