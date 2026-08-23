"""CLI tests. This surface previously had zero coverage (F-20, F-21)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from aegis_shield.cli.main import cli
from aegis_shield.core.tokens import TokenVerifier
from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def keys(runner: CliRunner, tmp_path: Path):
    priv, pub = tmp_path / "admin.pem", tmp_path / "admin.pub"
    result = runner.invoke(cli, ["keygen", str(priv), str(pub)])
    assert result.exit_code == 0, result.output
    return priv, pub


@pytest.fixture()
def namespace(runner: CliRunner, tmp_path: Path) -> Path:
    ns = tmp_path / "ns"
    result = runner.invoke(cli, ["provision", str(ns), "--blocks", "64"])
    assert result.exit_code == 0, result.output
    return ns


# ---------------------------------------------------------------------------
# provision / keygen / status
# ---------------------------------------------------------------------------

def test_provision_creates_namespace(namespace: Path) -> None:
    assert (namespace / "metadata.json").exists()
    assert (namespace / "base.img").exists()
    assert (namespace / "journal.jsonl").exists()


def test_provision_refuses_existing_directory(runner: CliRunner, namespace: Path) -> None:
    result = runner.invoke(cli, ["provision", str(namespace), "--blocks", "64"])
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_keygen_writes_both_halves(keys) -> None:
    priv, pub = keys
    assert b"PRIVATE KEY" in priv.read_bytes()
    assert b"PUBLIC KEY" in pub.read_bytes()
    TokenVerifier(pub.read_bytes())          # must load as Ed25519


def test_status_reports_json(runner: CliRunner, namespace: Path) -> None:
    result = runner.invoke(cli, ["status", str(namespace)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["device_id"]
    assert "writes_allowed" in payload


def test_status_does_not_mutate_the_audit_log(runner: CliRunner, namespace: Path) -> None:
    """A read-only command must not append audit events or advance state_version."""
    audit = namespace / "audit.jsonl"
    engine = AegisEngine(DurableJournal(namespace), Policy(PolicyConfig()), audit)
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")
    before = audit.read_bytes()
    version_before = engine.state_version
    del engine

    for _ in range(3):
        assert runner.invoke(cli, ["status", str(namespace)]).exit_code == 0

    assert audit.read_bytes() == before, "status must not append audit events"
    payload = json.loads(runner.invoke(cli, ["status", str(namespace)]).output)
    assert payload["state_version"] == version_before
    assert payload["state"] == "contained"
    assert payload["writes_allowed"] is False


# ---------------------------------------------------------------------------
# issue-token
# ---------------------------------------------------------------------------

def test_issue_token_defaults_to_recovery(runner: CliRunner, namespace: Path, keys) -> None:
    priv, pub = keys
    result = runner.invoke(
        cli, ["issue-token", str(namespace), str(priv), "--state-version", "1"]
    )
    assert result.exit_code == 0, result.output
    token = result.output.strip()
    assert token.startswith("aegis1.")

    auth = TokenVerifier(pub.read_bytes()).verify(
        token,
        device_id=DurableJournal(namespace).device_id,
        action="enter_recovery_read_only",
        state_version=1,
    )
    assert auth.target_sequence is not None


def test_issue_token_can_mint_maintenance_tokens(
    runner: CliRunner, namespace: Path, keys
) -> None:
    """The maintenance workflow must be reachable from shipped tooling."""
    priv, pub = keys
    result = runner.invoke(
        cli,
        [
            "issue-token", str(namespace), str(priv),
            "--state-version", "1", "--action", "enter_maintenance",
        ],
    )
    assert result.exit_code == 0, result.output

    auth = TokenVerifier(pub.read_bytes()).verify(
        result.output.strip(),
        device_id=DurableJournal(namespace).device_id,
        action="enter_maintenance",
        state_version=1,
    )
    assert auth.target_sequence is None, "a maintenance token carries no read anchor"


def test_issue_token_rejects_unknown_action(runner: CliRunner, namespace: Path, keys) -> None:
    priv, _pub = keys
    result = runner.invoke(
        cli,
        ["issue-token", str(namespace), str(priv), "--state-version", "1",
         "--action", "become_root"],
    )
    assert result.exit_code != 0


def test_issue_token_enforces_ttl_ceiling(runner: CliRunner, namespace: Path, keys) -> None:
    priv, _pub = keys
    result = runner.invoke(
        cli,
        ["issue-token", str(namespace), str(priv), "--state-version", "1",
         "--ttl-seconds", "99999"],
    )
    assert result.exit_code == 1
    assert "TTL cannot exceed" in result.output


# ---------------------------------------------------------------------------
# generate-trace / replay
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pattern",
    ["sequential_text", "high_entropy_append", "broad_overwrite", "low_and_slow"],
)
def test_generate_trace_all_patterns(
    runner: CliRunner, tmp_path: Path, pattern: str
) -> None:
    out = tmp_path / f"{pattern}.jsonl"
    result = runner.invoke(
        cli,
        ["generate-trace", str(out), "--pattern", pattern,
         "--blocks", "64", "--operations", "32"],
    )
    assert result.exit_code == 0, result.output

    events = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert events
    assert all(e["kind"] in {"read", "write"} for e in events)
    assert all("payload_b64" in e for e in events if e["kind"] == "write")


def test_generate_trace_is_deterministic(runner: CliRunner, tmp_path: Path) -> None:
    args = ["--pattern", "high_entropy_append", "--blocks", "64",
            "--operations", "16", "--seed", "7"]
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    runner.invoke(cli, ["generate-trace", str(a), *args])
    runner.invoke(cli, ["generate-trace", str(b), *args])
    assert a.read_bytes() == b.read_bytes()


def test_replay_runs_and_reports(runner: CliRunner, tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    runner.invoke(
        cli,
        ["generate-trace", str(trace), "--pattern", "sequential_text",
         "--blocks", "64", "--operations", "24"],
    )
    ns = tmp_path / "replay-ns"
    runner.invoke(cli, ["provision", str(ns), "--blocks", "64"])

    result = runner.invoke(cli, ["replay", str(ns), str(trace)])
    assert result.exit_code == 0, result.output
    assert "Replayed" in result.output
    assert "Final state:" in result.output


def test_replay_of_ransomware_like_trace_contains(runner: CliRunner, tmp_path: Path) -> None:
    """A broad, high-entropy overwrite campaign should trip containment."""
    trace = tmp_path / "attack.jsonl"
    runner.invoke(
        cli,
        ["generate-trace", str(trace), "--pattern", "broad_overwrite",
         "--blocks", "64", "--operations", "128"],
    )
    ns = tmp_path / "attack-ns"
    runner.invoke(cli, ["provision", str(ns), "--blocks", "64"])

    result = runner.invoke(cli, ["replay", str(ns), str(trace)])
    assert result.exit_code == 0, result.output
    assert "contained" in result.output.lower(), result.output
