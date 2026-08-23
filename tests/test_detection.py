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
    assert multi["min_true_positive_rate"] >= 0.75


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
