"""Pytest fixtures for Aegis Shield tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.policy import PolicyConfig


@pytest.fixture()
def journal(tmp_path: Path) -> DurableJournal:
    """A provisioned 256-block journal in a temporary directory."""
    return DurableJournal.provision(tmp_path / "ns", blocks=256, block_size=4096)


@pytest.fixture()
def policy() -> Policy:
    """Default production policy (containment disabled)."""
    return Policy(PolicyConfig())


@pytest.fixture()
def lab_policy() -> Policy:
    """Aggressive lab policy with containment enabled (low thresholds)."""
    return Policy(PolicyConfig.synthetic_demo())


@pytest.fixture()
def engine(journal: DurableJournal, policy: Policy, tmp_path: Path) -> AegisEngine:
    """A fully initialized AegisEngine backed by a temp journal."""
    return AegisEngine(journal, policy, tmp_path / "audit.jsonl")


@pytest.fixture()
def lab_engine(journal: DurableJournal, lab_policy: Policy, tmp_path: Path) -> AegisEngine:
    """A fully initialized AegisEngine with the aggressive lab policy."""
    return AegisEngine(journal, lab_policy, tmp_path / "lab_audit.jsonl")
