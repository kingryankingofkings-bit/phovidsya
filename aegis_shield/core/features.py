from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .entropy import changed_byte_fraction, shannon_entropy
from .types import FeatureVector, IoEvent, IoKind


@dataclass(frozen=True)
class AnalyzerConfig:
    window_operations: int = 128
    namespace_blocks: int = 1
    high_entropy_bits_per_byte: float = 7.5


@dataclass(frozen=True)
class _Observation:
    kind: IoKind
    lba: int
    blocks: int
    entropy: float = 0.0
    high_entropy: bool = False
    overwrite: bool = False
    changed_fraction: float = 0.0
    sequential: bool = False
    read_before_write: bool = False
    destructive: bool = False


class WindowAnalyzer:
    """Bounded, transparent feature extraction; no trained model is embedded."""

    def __init__(self, config: AnalyzerConfig):
        if config.window_operations < 1 or config.namespace_blocks < 1:
            raise ValueError("window_operations and namespace_blocks must be positive")
        self.config = config
        self._window: deque[_Observation] = deque(maxlen=config.window_operations)
        self._written_blocks: set[int] = set()
        self._recent_reads: deque[tuple[int, int]] = deque(maxlen=config.window_operations)
        self._last_write_end: int | None = None

    def observe(self, event: IoEvent, before: bytes | None = None) -> FeatureVector:
        entropy = 0.0
        overwrite = False
        change = 0.0
        sequential = False
        read_before_write = False

        if event.kind is IoKind.READ:
            self._recent_reads.append((event.lba, event.lba + event.blocks))
        elif event.kind is IoKind.WRITE:
            entropy = shannon_entropy(event.payload)
            covered = range(event.lba, event.lba + event.blocks)
            overwrite = any(block in self._written_blocks for block in covered)
            if before is not None:
                change = changed_byte_fraction(before, event.payload)
            sequential = self._last_write_end == event.lba
            read_before_write = any(
                event.lba < read_end and event.lba + event.blocks > read_start
                for read_start, read_end in self._recent_reads
            )
            self._written_blocks.update(covered)
            self._last_write_end = event.lba + event.blocks

        destructive = event.kind is IoKind.ADMIN or event.kind is IoKind.DEALLOCATE
        self._window.append(
            _Observation(
                kind=event.kind,
                lba=event.lba,
                blocks=event.blocks,
                entropy=entropy,
                high_entropy=entropy >= self.config.high_entropy_bits_per_byte,
                overwrite=overwrite,
                changed_fraction=change,
                sequential=sequential,
                read_before_write=read_before_write,
                destructive=destructive,
            )
        )
        return self.snapshot()

    def snapshot(self) -> FeatureVector:
        items = list(self._window)
        count = len(items)
        writes = [item for item in items if item.kind is IoKind.WRITE]
        write_count = len(writes)
        unique_write_blocks = {
            block for item in writes for block in range(item.lba, item.lba + item.blocks)
        }
        total_write_blocks = sum(item.blocks for item in writes)

        def ratio(numerator: float, denominator: float) -> float:
            return numerator / denominator if denominator else 0.0

        return FeatureVector(
            operations=count,
            write_fraction=ratio(write_count, count),
            mean_write_entropy=ratio(sum(item.entropy for item in writes), write_count),
            high_entropy_write_fraction=ratio(sum(item.high_entropy for item in writes), write_count),
            overwrite_fraction=ratio(sum(item.overwrite for item in writes), write_count),
            changed_byte_fraction=ratio(sum(item.changed_fraction for item in writes), write_count),
            unique_write_fraction=ratio(len(unique_write_blocks), total_write_blocks),
            namespace_coverage_fraction=min(
                1.0, ratio(len(unique_write_blocks), self.config.namespace_blocks)
            ),
            sequential_write_fraction=ratio(sum(item.sequential for item in writes), write_count),
            read_before_write_fraction=ratio(
                sum(item.read_before_write for item in writes), write_count
            ),
            deallocate_fraction=ratio(
                sum(item.kind is IoKind.DEALLOCATE for item in items), count
            ),
            destructive_command_seen=any(item.destructive for item in items),
        )
