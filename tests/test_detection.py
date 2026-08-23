"""Detection-behaviour tests: the measured properties of the shipped policy.

These lock in what the synthetic benchmark establishes, so a future weight or
threshold change cannot silently reintroduce a false positive on legitimate
high-entropy data — the failure mode that freezes a healthy machine.

They measure behaviour against SYNTHETIC workloads. They say nothing about real
ransomware; see docs/DETECTION.md.
"""

from __future__ import annotations

import pytest

from aegis_shield.core.benchmark import run_benchmark, run_multi_seed
from aegis_shield.core.policy import Policy, PolicyConfig
from aegis_shield.core.workloads import ALL, BENIGN, RANSOMWARE

# Peak scores vary by <= 0.001 across seeds (the workloads are deterministic in
# shape), so four draws carry the same signal as twelve at a third of the cost.
# `aegis-shield benchmark` defaults to twelve for reporting.
SEEDS = tuple(range(1, 5))


@pytest.fixture(scope="module")
def report():
    return run_benchmark()


@pytest.fixture(scope="module")
def multi():
    return run_multi_seed(seeds=SEEDS)


# ---------------------------------------------------------------------------
# The property that matters most: do not freeze healthy machines
# ---------------------------------------------------------------------------

def test_no_false_positives_across_seeds(multi) -> None:
    assert multi["max_false_positive_rate"] == 0.0


@pytest.mark.parametrize("workload", [w.name for w in BENIGN])
def test_each_benign_workload_is_not_contained(report, workload: str) -> None:
    result = next(r for r in report.results if r.name == workload)
    assert not result.contained, (
        f"{workload} would freeze the device (peak {result.peak_score:.3f} >= "
        f"{report.config.containment_threshold})"
    )


def test_high_entropy_benign_data_is_not_contained(report) -> None:
    """Compressed archives, media, and encrypted stores are ~8 bits/byte and benign."""
    for name in ("archive_copy", "media_import", "encrypted_volume_fill"):
        result = next(r for r in report.results if r.name == name)
        assert result.peak_features["mean_write_entropy"] > 7.5, "should be high entropy"
        assert not result.contained, f"{name} must not trigger containment"


def test_containment_has_real_headroom(multi) -> None:
    """A margin of a few thousandths is not a safety margin.

    Before the weights were measured this was +0.004: copying a tarball scored
    0.816 against a 0.820 threshold.
    """
    assert multi["containment_margin"] >= 0.05, (
        f"only {multi['containment_margin']:+.3f} between the loudest benign "
        "workload and the containment threshold"
    )


def test_alert_threshold_is_quiet_on_benign_traffic(report) -> None:
    """An alert that fires on routine work is an alert that gets ignored."""
    noisy = [r.name for r in report.benign if r.alerted]
    assert not noisy, f"alert fires on benign workloads: {noisy}"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_canonical_encryption_sweep_is_contained(report) -> None:
    result = next(r for r in report.results if r.name == "encrypt_in_place")
    assert result.contained


def test_encrypt_and_wipe_is_contained(report) -> None:
    result = next(r for r in report.results if r.name == "encrypt_and_wipe")
    assert result.contained


def test_targeted_encryption_is_contained(report) -> None:
    """Narrow-scope encryption must still be caught, despite low coverage."""
    result = next(r for r in report.results if r.name == "targeted_documents")
    assert result.contained


def test_true_positive_rate_does_not_regress(multi) -> None:
    """60%, not 75%: the corpus now includes the minimal evasion case.

    That is the corpus becoming more honest, not the detector getting worse.
    Two of five ransomware workloads escape containment, and both do so by
    interleaving benign writes.
    """
    assert multi["min_true_positive_rate"] >= 0.60


def test_one_interleaved_write_defeats_containment(report) -> None:
    """A single benign write per encryption escapes containment.

    This is the cheapest evasion that works, and it bounds how much effort the
    current design demands of an attacker: almost none. Pinned so the cost of
    evasion stays visible rather than being rediscovered later.

    It does still ALERT — escaping containment is not the same as being
    invisible — which is why the alert threshold sits at 0.72 rather than
    being merged into the containment threshold.
    """
    result = next(r for r in report.results if r.name == "minimal_evasion")
    assert not result.contained, (
        "minimal_evasion is now contained — good news; update docs/DETECTION.md, "
        "which documents it as a known gap"
    )
    assert result.alerted, "evasion below containment must at least raise ELEVATED"


def test_window_size_cannot_close_the_dilution_gap() -> None:
    """Enlarging the window does not bring a diluted attack up to containment.

    A windowed *mean* is close to ratio-invariant: averaging over more
    operations at the same malicious:benign ratio yields nearly the same
    average. Measured over a 1:2 interleave, growing the window 128 -> 512
    moves the peak by only ~0.06 and then plateaus (1024 scores below 512),
    while roughly 0.18 would be needed to reach the 0.82 threshold.

    So window size is not the lever. Any fix has to *accumulate* evidence
    across the campaign rather than average it away.
    """
    import random

    from aegis_shield.core.features import AnalyzerConfig, WindowAnalyzer
    from aegis_shield.core.types import IoEvent, IoKind
    from aegis_shield.core.workloads import _incompressible, _text

    def peak(window: int) -> float:
        analyzer = WindowAnalyzer(
            AnalyzerConfig(window_operations=window, namespace_blocks=512)
        )
        policy = Policy(PolicyConfig())
        rng = random.Random(7)
        written = {b: _text(rng, 4096, "user") for b in range(512)}
        best = 0.0
        for i in range(1200):
            if i % 3 == 0:
                target = (i * 7) % 512
                analyzer.observe(IoEvent(IoKind.READ, target, 1, b"", 0))
                event = IoEvent(IoKind.WRITE, target, 1, _incompressible(rng, 4096), 0)
            else:
                target = i % 512
                event = IoEvent(IoKind.WRITE, target, 1, _text(rng, 4096), 0)
            features = analyzer.observe(event, before=written.get(target, bytes(4096)))
            written[target] = event.payload
            best = max(best, policy.evaluate(features).score)
        return best

    baseline, enlarged, huge = peak(128), peak(512), peak(1024)
    threshold = PolicyConfig().containment_threshold

    # A 4x window buys a little, but nowhere near enough.
    assert enlarged - baseline < 0.10, "window growth helped more than measured"
    assert enlarged < threshold, (
        f"a 512-op window now reaches containment ({enlarged:.3f} >= {threshold}) "
        "— revisit docs/DETECTION.md, which says window size cannot close the gap"
    )
    # And it plateaus: 8x is no better than 4x.
    assert huge <= enlarged + 0.02, "returns did not diminish as documented"


def test_evasive_workload_is_documented_as_missed(report) -> None:
    """low_and_slow is NOT caught. This test asserts the known limitation.

    Interleaving benign traffic with encryption dilutes every windowed signal.
    If a future change catches it, that is good news — update this test and
    docs/DETECTION.md rather than deleting the honesty.
    """
    result = next(r for r in report.results if r.name == "low_and_slow")
    assert not result.contained, (
        "low_and_slow is now caught — update docs/DETECTION.md, which documents "
        "it as a known gap"
    )


# ---------------------------------------------------------------------------
# The mechanism the weighting depends on
# ---------------------------------------------------------------------------

def test_entropy_alone_cannot_discriminate(report) -> None:
    """The premise of the weighting: benign and malicious payloads are identical.

    If this ever stops being true the weighting should be revisited — but it
    will not, because compression and encryption both produce ~8 bits/byte.
    """
    benign = next(r for r in report.results if r.name == "archive_copy")
    attack = next(r for r in report.results if r.name == "encrypt_in_place")
    assert abs(
        benign.peak_features["mean_write_entropy"]
        - attack.peak_features["mean_write_entropy"]
    ) < 0.1


def test_read_before_write_is_the_discriminator(report) -> None:
    benign = next(r for r in report.results if r.name == "archive_copy")
    attack = next(r for r in report.results if r.name == "encrypt_in_place")
    assert benign.peak_features["read_before_write_fraction"] == 0.0
    assert attack.peak_features["read_before_write_fraction"] > 0.9


def test_behavioural_weights_dominate_content_weights() -> None:
    weights = PolicyConfig().weights
    content = weights["entropy"] + weights["high_entropy"] + weights["changed"]
    behaviour = (
        weights["read_before_write"] + weights["overwrite"] + weights["coverage"]
    )
    assert behaviour > content, (
        "content signals cannot carry the decision; a compressed archive and an "
        "encrypted file are indistinguishable by content"
    )


def test_weights_sum_to_one() -> None:
    assert abs(sum(PolicyConfig().weights.values()) - 1.0) < 1e-9


def test_all_weights_are_known_to_the_policy() -> None:
    Policy(PolicyConfig())  # raises on an unknown weight name


# ---------------------------------------------------------------------------
# Corpus integrity
# ---------------------------------------------------------------------------

def test_every_workload_produces_operations(report) -> None:
    for result in report.results:
        assert result.operations >= 100, f"{result.name} generated too few operations"


def test_workloads_are_deterministic() -> None:
    a = run_benchmark(seed=42)
    b = run_benchmark(seed=42)
    assert [r.peak_score for r in a.results] == [r.peak_score for r in b.results]


def test_corpus_covers_both_classes() -> None:
    assert len(BENIGN) >= 5 and len(RANSOMWARE) >= 4
    assert len(ALL) == len(BENIGN) + len(RANSOMWARE)
