from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SizingResult:
    pcie_encoding_ceiling_bytes_s: float
    payload_iops_ceiling: float
    ideal_journal_seconds: float
    maximum_pending_blocks: int
    overlay_map_bytes: int
    proxy_write_amplification_lower_bound: float

    def to_dict(self) -> dict:
        return asdict(self)


def size_gen2_design(
    *,
    lanes: int,
    logical_block_bytes: int,
    journal_bytes: int,
    sustained_unique_write_bytes_s: float,
    map_entry_bytes: int,
    metadata_bytes_per_logical_block: float = 0.0,
    retained_version_bytes_per_logical_block: float = 0.0,
) -> SizingResult:
    values = (
        lanes,
        logical_block_bytes,
        journal_bytes,
        sustained_unique_write_bytes_s,
        map_entry_bytes,
    )
    if any(value <= 0 for value in values):
        raise ValueError("all primary sizing inputs must be positive")
    if logical_block_bytes & (logical_block_bytes - 1):
        raise ValueError("logical_block_bytes must be a power of two")
    if metadata_bytes_per_logical_block < 0 or retained_version_bytes_per_logical_block < 0:
        raise ValueError("overhead inputs cannot be negative")
    ceiling = lanes * 5_000_000_000 * (8 / 10) / 8
    maximum_pending = journal_bytes // logical_block_bytes
    amplification = 2.0 + (
        metadata_bytes_per_logical_block + retained_version_bytes_per_logical_block
    ) / logical_block_bytes
    return SizingResult(
        pcie_encoding_ceiling_bytes_s=ceiling,
        payload_iops_ceiling=ceiling / logical_block_bytes,
        ideal_journal_seconds=journal_bytes / sustained_unique_write_bytes_s,
        maximum_pending_blocks=maximum_pending,
        overlay_map_bytes=maximum_pending * map_entry_bytes,
        proxy_write_amplification_lower_bound=amplification,
    )
