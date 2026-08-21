from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class AegisState(str, Enum):
    BOOT_SELFTEST = "boot_selftest"
    PROVISIONING = "provisioning"
    NORMAL = "normal"
    ELEVATED = "elevated"
    CONTAINED = "contained"
    RECOVERY_READ_ONLY = "recovery_read_only"
    MAINTENANCE = "maintenance"
    FAULT = "fault"


class IoKind(str, Enum):
    READ = "read"
    WRITE = "write"
    FLUSH = "flush"
    DEALLOCATE = "deallocate"
    ADMIN = "admin"


@dataclass(frozen=True)
class IoEvent:
    kind: IoKind
    lba: int = 0
    blocks: int = 0
    payload: bytes = b""
    timestamp_ns: int = 0
    opcode: int | None = None


@dataclass(frozen=True)
class FeatureVector:
    operations: int
    write_fraction: float
    mean_write_entropy: float
    high_entropy_write_fraction: float
    overwrite_fraction: float
    changed_byte_fraction: float
    unique_write_fraction: float
    namespace_coverage_fraction: float
    sequential_write_fraction: float
    read_before_write_fraction: float
    deallocate_fraction: float
    destructive_command_seen: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    score: float
    alert: bool
    contain: bool
    reasons: tuple[str, ...]
    features: FeatureVector

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["features"] = self.features.to_dict()
        return value
