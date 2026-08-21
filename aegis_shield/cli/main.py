"""Aegis Shield CLI — provision, start, monitor and manage the ransomware isolation engine."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click


@click.group()
@click.version_option(package_name="aegis-shield")
def cli() -> None:
    """Aegis Shield — hardware-grade ransomware isolation, software reference deployment."""


@cli.command()
@click.argument("namespace_dir", type=click.Path(path_type=Path))
@click.option("--blocks", required=True, type=int, help="Namespace size in blocks")
@click.option("--block-size", default=4096, show_default=True, type=int)
@click.option("--device-id", default=None, help="Optional deterministic device UUID")
def provision(namespace_dir: Path, blocks: int, block_size: int, device_id: Optional[str]) -> None:
    """Provision a new file-backed virtual storage namespace."""
    from ..core.journal import DurableJournal

    if namespace_dir.exists():
        click.echo(f"[error] {namespace_dir} already exists. Remove it first.", err=True)
        sys.exit(1)
    journal = DurableJournal.provision(namespace_dir, blocks=blocks, block_size=block_size, device_id=device_id)
    click.echo(f"Provisioned namespace: {namespace_dir}")
    click.echo(f"  device_id  : {journal.device_id}")
    click.echo(f"  blocks     : {journal.blocks}")
    click.echo(f"  block_size : {journal.block_size}")


@cli.command()
@click.argument("namespace_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8443, show_default=True, type=int)
@click.option("--public-key", default=None, type=click.Path(path_type=Path))
@click.option("--policy-config", default=None, type=click.Path(path_type=Path))
@click.option("--blocks", default=1024, show_default=True, type=int)
def start(
    namespace_dir: Path,
    host: str,
    port: int,
    public_key: Optional[Path],
    policy_config: Optional[Path],
    blocks: int,
) -> None:
    """Start the Aegis Shield daemon and REST API server."""
    from ..daemon.service import AegisDaemon
    from ..core.config import load_policy
    from ..core.policy import PolicyConfig

    audit_path = namespace_dir / "audit.jsonl"
    policy_cfg = load_policy(policy_config) if policy_config else PolicyConfig()

    daemon = AegisDaemon(
        namespace_dir=namespace_dir,
        audit_path=audit_path,
        host=host,
        port=port,
        blocks=blocks,
        public_key_path=public_key,
        policy_config=policy_cfg,
    )
    click.echo(f"Starting Aegis Shield on {host}:{port} — namespace {namespace_dir}")
    daemon.run()


@cli.command()
@click.argument("namespace_dir", type=click.Path(exists=True, path_type=Path))
def status(namespace_dir: Path) -> None:
    """Show the current engine status for a provisioned namespace."""
    from ..core.journal import DurableJournal
    from ..core.engine import AegisEngine
    from ..core.policy import Policy, PolicyConfig

    journal = DurableJournal(namespace_dir)
    engine = AegisEngine(journal, Policy(PolicyConfig()), namespace_dir / "audit.jsonl")
    info = engine.status()
    click.echo(json.dumps(info, indent=2))


@cli.command()
@click.argument("private", type=click.Path(path_type=Path))
@click.argument("public", type=click.Path(path_type=Path))
def keygen(private: Path, public: Path) -> None:
    """Generate an Ed25519 keypair for recovery token signing."""
    from ..core.tokens import generate_keypair

    generate_keypair(private, public)
    click.echo(f"Private key: {private}")
    click.echo(f"Public key : {public}")
    click.echo("Keep the private key offline and off the protected host.")


@cli.command("issue-token")
@click.argument("namespace_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("private_key", type=click.Path(exists=True, path_type=Path))
@click.option("--state-version", required=True, type=int)
@click.option("--target-sequence", default=None, type=int)
@click.option("--ttl-seconds", default=600, show_default=True, type=int)
def issue_token(
    namespace_dir: Path,
    private_key: Path,
    state_version: int,
    target_sequence: Optional[int],
    ttl_seconds: int,
) -> None:
    """Issue a short-lived signed recovery authorization token."""
    import time
    from dataclasses import asdict
    from ..core.journal import DurableJournal
    from ..core.tokens import RecoveryAuthorization, sign_authorization
    import secrets

    if ttl_seconds > 900:
        click.echo("[error] TTL cannot exceed 900 seconds.", err=True)
        sys.exit(1)

    journal = DurableJournal(namespace_dir)
    now = int(time.time())
    authorization = RecoveryAuthorization(
        action="enter_recovery_read_only",
        device_id=journal.device_id,
        expires_unix=now + ttl_seconds,
        issued_unix=now,
        nonce=secrets.token_hex(16),
        state_version=state_version,
        target_sequence=target_sequence if target_sequence is not None else journal.last_sequence,
    )
    token = sign_authorization(authorization, private_key.read_bytes())
    click.echo(token)


@cli.command("generate-trace")
@click.argument("output", type=click.Path(path_type=Path))
@click.option("--pattern", required=True,
              type=click.Choice(["sequential_text", "high_entropy_append", "broad_overwrite", "low_and_slow"]))
@click.option("--blocks", default=256, show_default=True, type=int)
@click.option("--block-size", default=4096, show_default=True, type=int)
@click.option("--operations", default=64, show_default=True, type=int)
@click.option("--seed", default=1, show_default=True, type=int)
def generate_trace(output: Path, pattern: str, blocks: int, block_size: int, operations: int, seed: int) -> None:
    """Generate a deterministic synthetic (non-malware) I/O trace."""
    from ..core.tracegen import synthetic_trace, write_trace

    trace = synthetic_trace(pattern=pattern, blocks=blocks, block_size=block_size, operations=operations, seed=seed)
    write_trace(output, trace)
    click.echo(f"Wrote {len(trace)} operations to {output}")


@cli.command()
@click.argument("namespace_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("trace_file", type=click.Path(exists=True, path_type=Path))
@click.option("--policy-config", default=None, type=click.Path(path_type=Path))
def replay(namespace_dir: Path, trace_file: Path, policy_config: Optional[Path]) -> None:
    """Replay a synthetic I/O trace into a provisioned namespace."""
    import json as _json
    import base64 as _b64
    from ..core.journal import DurableJournal
    from ..core.engine import AegisEngine
    from ..core.policy import Policy, PolicyConfig
    from ..core.config import load_policy

    journal = DurableJournal(namespace_dir)
    policy_cfg = load_policy(policy_config) if policy_config else PolicyConfig()
    engine = AegisEngine(journal, Policy(policy_cfg), namespace_dir / "audit.jsonl")

    trace = []
    with trace_file.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                trace.append(_json.loads(line))

    decisions = []
    for op in trace:
        if op["kind"] == "write":
            payload = _b64.b64decode(op["payload_b64"])
            try:
                d = engine.write(op["lba"], payload)
                decisions.append(d)
            except PermissionError as exc:
                click.echo(f"  BLOCKED lba={op['lba']}: {exc}", err=True)
        elif op["kind"] == "read":
            engine.read(op["lba"], op.get("blocks", 1))

    alert_count = sum(1 for d in decisions if d.alert)
    contain_count = sum(1 for d in decisions if d.contain)
    click.echo(f"Replayed {len(decisions)} writes — alerts: {alert_count}, containments: {contain_count}")
    click.echo(f"Final state: {engine.state.value}")


if __name__ == "__main__":
    cli()
