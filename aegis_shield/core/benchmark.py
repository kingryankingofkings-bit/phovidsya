"""Measure policy behaviour against the synthetic workload corpus.

This produces a *false-positive rate against synthetic benign workloads* and a
*true-positive rate against synthetic ransomware-shaped workloads*. It does not
measure efficacy against real ransomware — see ``docs/DETECTION.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import random

from .features import AnalyzerConfig, WindowAnalyzer
from .policy import Policy, PolicyConfig
from .types import IoKind
from .workloads import ALL, Workload, _text


@dataclass(frozen=True)
class WorkloadResult:
    name: str
    kind: str
    description: str
    peak_score: float
    mean_score: float
    alerted: bool
    contained: bool
    operations: int
    peak_features: dict = field(repr=False, default_factory=dict)

    @property
    def correct(self) -> bool:
        """Containment is the decision under test: fire on attack, stay quiet otherwise."""
        return self.contained if self.kind == "ransomware" else not self.contained


@dataclass(frozen=True)
class BenchmarkReport:
    results: tuple[WorkloadResult, ...]
    config: PolicyConfig

    @property
    def benign(self) -> tuple[WorkloadResult, ...]:
        return tuple(r for r in self.results if r.kind == "benign")

    @property
    def ransomware(self) -> tuple[WorkloadResult, ...]:
        return tuple(r for r in self.results if r.kind == "ransomware")

    @property
    def false_positives(self) -> tuple[WorkloadResult, ...]:
        return tuple(r for r in self.benign if r.contained)

    @property
    def false_negatives(self) -> tuple[WorkloadResult, ...]:
        return tuple(r for r in self.ransomware if not r.contained)

    @property
    def false_positive_rate(self) -> float:
        return len(self.false_positives) / len(self.benign) if self.benign else 0.0

    @property
    def true_positive_rate(self) -> float:
        caught = len(self.ransomware) - len(self.false_negatives)
        return caught / len(self.ransomware) if self.ransomware else 0.0

    @property
    def separation(self) -> float:
        """Gap between the quietest attack and the loudest benign workload.

        Positive means a threshold exists that separates the two sets cleanly.
        Negative means no single threshold can, and the sets overlap.
        """
        if not self.benign or not self.ransomware:
            return 0.0
        return min(r.peak_score for r in self.ransomware) - max(
            r.peak_score for r in self.benign
        )


def run_workload(
    workload: Workload,
    config: PolicyConfig,
    *,
    blocks: int = 512,
    block_size: int = 4096,
    seed: int = 1,
) -> WorkloadResult:
    """Score one workload through the real analyzer and policy."""
    analyzer = WindowAnalyzer(AnalyzerConfig(namespace_blocks=blocks))
    policy = Policy(config)

    peak = 0.0
    total = 0.0
    scored = 0
    alerted = contained = False
    peak_features: dict = {}

    # Model a device IN SERVICE, not a blank one. A freshly provisioned
    # namespace is all zeros, which makes "this write replaced existing data"
    # false for every first-touch block — and ransomware touches most blocks
    # exactly once. Benchmarking against a blank device would therefore hide the
    # single most discriminating signal. Pre-fill with plausible user content.
    seed_rng = random.Random(seed ^ 0x5EED)
    written: dict[int, bytes] = {
        block: _text(seed_rng, block_size, "user")
        for block in range(blocks)
    }

    for event in workload.generate(blocks, block_size, seed):
        before = None
        if event.kind is IoKind.WRITE:
            before = written.get(event.lba, bytes(block_size))
        features = analyzer.observe(event, before=before)
        if event.kind is IoKind.WRITE:
            written[event.lba] = event.payload

        decision = policy.evaluate(features)
        total += decision.score
        scored += 1
        if decision.score > peak:
            peak = decision.score
            peak_features = features.to_dict()
        alerted = alerted or decision.alert
        contained = contained or decision.contain

    return WorkloadResult(
        name=workload.name,
        kind=workload.kind,
        description=workload.description,
        peak_score=peak,
        mean_score=total / scored if scored else 0.0,
        alerted=alerted,
        contained=contained,
        operations=scored,
        peak_features=peak_features,
    )


def run_benchmark(
    config: PolicyConfig | None = None,
    *,
    workloads: tuple[Workload, ...] = ALL,
    blocks: int = 512,
    block_size: int = 4096,
    seed: int = 1,
) -> BenchmarkReport:
    resolved = config or PolicyConfig()
    return BenchmarkReport(
        results=tuple(
            run_workload(w, resolved, blocks=blocks, block_size=block_size, seed=seed)
            for w in workloads
        ),
        config=resolved,
    )


def run_multi_seed(
    config: PolicyConfig | None = None,
    *,
    seeds: tuple[int, ...] = tuple(range(1, 13)),
    blocks: int = 512,
    block_size: int = 4096,
) -> dict:
    """Run the corpus across several seeds.

    A single seed measures one RNG draw, not the workload. Tuning against one
    draw is overfitting; this reports the worst case across many, which is the
    number that matters for a containment decision.
    """
    reports = [
        run_benchmark(config, blocks=blocks, block_size=block_size, seed=s) for s in seeds
    ]
    per_workload: dict[str, list[float]] = {}
    for report in reports:
        for result in report.results:
            per_workload.setdefault(result.name, []).append(result.peak_score)

    benign_names = {r.name for r in reports[0].benign}
    worst_benign = max(
        max(scores) for name, scores in per_workload.items() if name in benign_names
    )
    worst_attack = min(
        min(scores) for name, scores in per_workload.items() if name not in benign_names
    )
    return {
        "seeds": len(seeds),
        "reports": reports,
        "per_workload": per_workload,
        "loudest_benign": worst_benign,
        "quietest_attack": worst_attack,
        "separation": worst_attack - worst_benign,
        "max_false_positive_rate": max(r.false_positive_rate for r in reports),
        "min_true_positive_rate": min(r.true_positive_rate for r in reports),
        "containment_margin": reports[0].config.containment_threshold - worst_benign,
    }


def format_report(report: BenchmarkReport) -> str:
    """Render a report as an aligned text table."""
    width = max(len(r.name) for r in report.results)
    lines = [
        f"{'WORKLOAD':<{width}}  {'KIND':<10} {'PEAK':>6} {'MEAN':>6}  "
        f"{'ALERT':<6} {'CONTAIN':<8} VERDICT",
        "-" * (width + 48),
    ]
    for result in sorted(report.results, key=lambda r: (r.kind, -r.peak_score)):
        verdict = "ok" if result.correct else (
            "FALSE POSITIVE" if result.kind == "benign" else "MISSED"
        )
        lines.append(
            f"{result.name:<{width}}  {result.kind:<10} {result.peak_score:>6.3f} "
            f"{result.mean_score:>6.3f}  {str(result.alerted):<6} "
            f"{str(result.contained):<8} {verdict}"
        )
    lines += [
        "",
        f"alert threshold      : {report.config.alert_threshold:.2f}",
        f"containment threshold: {report.config.containment_threshold:.2f}",
        f"containment enabled  : {report.config.containment_enabled}",
        "",
        f"true-positive rate   : {report.true_positive_rate:.0%} "
        f"({len(report.ransomware) - len(report.false_negatives)}/{len(report.ransomware)})",
        f"false-positive rate  : {report.false_positive_rate:.0%} "
        f"({len(report.false_positives)}/{len(report.benign)})",
        f"separation           : {report.separation:+.3f} "
        f"(quietest attack minus loudest benign)",
    ]
    return "\n".join(lines)
