from __future__ import annotations

from dataclasses import dataclass, field

from .types import Decision, FeatureVector


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass(frozen=True)
class PolicyConfig:
    """Policy coefficients are engineering inputs, not validated efficacy data."""

    minimum_operations: int = 16
    alert_threshold: float = 0.65
    # 0.82 is deliberately well above the ~0.65 that sustained random-entropy
    # writes produce, so containment needs several corroborating signals.
    containment_threshold: float = 0.82
    containment_enabled: bool = True
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "entropy": 0.18,
            "high_entropy": 0.14,
            "overwrite": 0.16,
            "changed": 0.12,
            "coverage": 0.14,
            "read_before_write": 0.12,
            "write_fraction": 0.08,
            "deallocate": 0.06,
        }
    )

    @classmethod
    def synthetic_demo(cls) -> "PolicyConfig":
        """Aggressive LAB-ONLY policy used to exercise containment deterministically."""
        return cls(
            minimum_operations=8,
            alert_threshold=0.45,
            containment_threshold=0.60,
            containment_enabled=True,
        )


class Policy:
    def __init__(self, config: PolicyConfig | None = None):
        self.config = config or PolicyConfig()
        allowed_weights = {
            "entropy",
            "high_entropy",
            "overwrite",
            "changed",
            "coverage",
            "read_before_write",
            "write_fraction",
            "deallocate",
        }
        unknown_weights = set(self.config.weights) - allowed_weights
        if unknown_weights:
            raise ValueError(f"unknown policy weights: {sorted(unknown_weights)}")
        if not 0 <= self.config.alert_threshold <= self.config.containment_threshold <= 1:
            raise ValueError("thresholds must satisfy 0 <= alert <= containment <= 1")
        if any(weight < 0 for weight in self.config.weights.values()):
            raise ValueError("weights must be non-negative")

    def evaluate(self, f: FeatureVector) -> Decision:
        if f.destructive_command_seen:
            return Decision(1.0, True, self.config.containment_enabled, ("destructive command",), f)
        if f.operations < self.config.minimum_operations:
            return Decision(0.0, False, False, ("insufficient window",), f)

        components = {
            "entropy": _clamp((f.mean_write_entropy - 6.0) / 2.0),
            "high_entropy": f.high_entropy_write_fraction,
            "overwrite": f.overwrite_fraction,
            "changed": f.changed_byte_fraction,
            "coverage": _clamp(f.namespace_coverage_fraction * 20.0),
            "read_before_write": f.read_before_write_fraction,
            "write_fraction": f.write_fraction,
            "deallocate": _clamp(f.deallocate_fraction * 10.0),
        }
        total_weight = sum(self.config.weights.values()) or 1.0
        score = sum(
            components.get(name, 0.0) * weight
            for name, weight in self.config.weights.items()
        ) / total_weight
        reasons = tuple(
            name for name, value in sorted(components.items()) if value >= 0.75
        ) or ("combined weak signals",)
        alert = score >= self.config.alert_threshold
        contain = self.config.containment_enabled and score >= self.config.containment_threshold
        return Decision(score, alert, contain, reasons, f)
