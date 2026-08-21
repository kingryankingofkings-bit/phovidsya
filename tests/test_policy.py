"""Policy unit tests."""

from __future__ import annotations

from aegis_shield.core.policy import Policy, PolicyConfig
from aegis_shield.core.types import FeatureVector


def _fv(**overrides) -> FeatureVector:
    defaults = dict(
        operations=64, write_fraction=0.5, mean_write_entropy=4.0,
        high_entropy_write_fraction=0.0, overwrite_fraction=0.0,
        changed_byte_fraction=0.0, unique_write_fraction=0.5,
        namespace_coverage_fraction=0.0, sequential_write_fraction=0.8,
        read_before_write_fraction=0.0, deallocate_fraction=0.0,
        destructive_command_seen=False,
    )
    defaults.update(overrides)
    return FeatureVector(**defaults)


def test_low_entropy_writes_no_alert() -> None:
    policy = Policy(PolicyConfig())
    fv = _fv(operations=64, mean_write_entropy=3.5, high_entropy_write_fraction=0.0,
             overwrite_fraction=0.0, changed_byte_fraction=0.1, sequential_write_fraction=0.95)
    decision = policy.evaluate(fv)
    assert not decision.alert
    assert not decision.contain
    assert decision.score < policy.config.alert_threshold


def test_insufficient_operations_no_alert() -> None:
    policy = Policy(PolicyConfig(minimum_operations=32))
    fv = _fv(operations=8)
    decision = policy.evaluate(fv)
    assert decision.score == 0.0
    assert not decision.alert
    assert "insufficient window" in decision.reasons


def test_high_entropy_broad_overwrite_alert() -> None:
    policy = Policy(PolicyConfig())
    fv = _fv(operations=128, mean_write_entropy=7.9, high_entropy_write_fraction=0.95,
             overwrite_fraction=0.85, changed_byte_fraction=0.90,
             namespace_coverage_fraction=0.80, read_before_write_fraction=0.70,
             write_fraction=0.90, deallocate_fraction=0.0)
    decision = policy.evaluate(fv)
    assert decision.alert
    assert decision.score >= policy.config.alert_threshold


def test_lab_policy_containment_threshold() -> None:
    policy = Policy(PolicyConfig.synthetic_demo())
    assert policy.config.containment_enabled
    fv = _fv(operations=64, mean_write_entropy=7.8, high_entropy_write_fraction=0.92,
             overwrite_fraction=0.88, changed_byte_fraction=0.85,
             namespace_coverage_fraction=0.70, read_before_write_fraction=0.60,
             write_fraction=0.88)
    decision = policy.evaluate(fv)
    assert decision.contain
    assert decision.score >= policy.config.containment_threshold


def test_lab_policy_no_containment_below_threshold() -> None:
    policy = Policy(PolicyConfig.synthetic_demo())
    fv = _fv(operations=64, mean_write_entropy=5.0, high_entropy_write_fraction=0.2,
             overwrite_fraction=0.1, changed_byte_fraction=0.2)
    decision = policy.evaluate(fv)
    assert not decision.contain


def test_destructive_command_maxes_score() -> None:
    policy = Policy(PolicyConfig())
    fv = _fv(destructive_command_seen=True, operations=4)
    decision = policy.evaluate(fv)
    assert decision.score == 1.0
    assert decision.alert
    assert "destructive command" in decision.reasons


def test_destructive_command_contained_only_with_lab_policy() -> None:
    production_policy = Policy(PolicyConfig(containment_enabled=False))
    lab_policy = Policy(PolicyConfig.synthetic_demo())
    fv = _fv(destructive_command_seen=True)
    assert not production_policy.evaluate(fv).contain
    assert lab_policy.evaluate(fv).contain
