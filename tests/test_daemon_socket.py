"""Unix control-socket tests driven over a real socket, not by calling the handler.

The socket is the physical-presence barrier: every sensitive operation is
reachable only from a local shell. Previously these commands were exercised only
by calling ``_handle_socket_command`` directly, so the socket server itself, its
framing, and its error handling were untested.
"""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time
from pathlib import Path

import pytest
import yaml

from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.config import load_policy
from aegis_shield.core.tokens import (
    RecoveryAuthorization,
    generate_keypair,
    sign_authorization,
)
from aegis_shield.daemon.service import AegisDaemon

BLOCK_SIZE = 4096


@pytest.fixture()
def live_socket(tmp_path: Path):
    """Run the real Unix socket server in a thread; yield (send, engine, priv)."""
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    journal = DurableJournal.provision(tmp_path / "ns", blocks=32, block_size=BLOCK_SIZE)
    engine = AegisEngine(journal, Policy(PolicyConfig()), tmp_path / "audit.jsonl")

    sock_path = tmp_path / "aegis.sock"
    daemon = AegisDaemon(
        namespace_dir=tmp_path / "ns",
        audit_path=tmp_path / "audit.jsonl",
        public_key_path=pub,
        unix_socket_path=sock_path,
    )
    thread = threading.Thread(
        target=daemon._serve_unix_socket, args=(engine,), daemon=True
    )
    thread.start()
    for _ in range(100):
        if sock_path.exists():
            break
        time.sleep(0.02)

    def send(command: str) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(sock_path))
            client.sendall(command.encode())
            chunks = b""
            while not chunks.endswith(b"\n"):
                part = client.recv(65536)
                if not part:
                    break
                chunks += part
            return json.loads(chunks.decode())

    yield send, engine, priv
    daemon._shutdown_event.set()
    thread.join(timeout=3)


def _token(engine: AegisEngine, priv: Path, action: str, target=None) -> str:
    now = int(time.time())
    return sign_authorization(
        RecoveryAuthorization(
            action=action,
            device_id=engine.journal.device_id,
            expires_unix=now + 120,
            issued_unix=now,
            nonce=secrets.token_hex(16),
            state_version=engine.state_version,
            target_sequence=target,
        ),
        priv.read_bytes(),
    )


# ---------------------------------------------------------------------------

def test_status_over_socket(live_socket) -> None:
    send, engine, _priv = live_socket
    reply = send("status")
    assert reply["device_id"] == engine.journal.device_id
    assert reply["state"] == "normal"


def test_unknown_command_is_an_error(live_socket) -> None:
    send, _engine, _priv = live_socket
    assert "error" in send("please-do-something-else")


def test_full_recovery_workflow_over_socket(live_socket) -> None:
    """contained -> recovery_read_only -> maintenance -> normal, all locally."""
    send, engine, priv = live_socket
    engine.write(0, b"DATA".ljust(BLOCK_SIZE, b"."))
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")
    assert send("status")["state"] == "contained"

    token = _token(engine, priv, "enter_recovery_read_only", engine.journal.last_sequence)
    assert send(f"authorize {token}")["authorized"] is True
    assert send("status")["state"] == "recovery_read_only"

    token = _token(engine, priv, "enter_maintenance")
    assert send(f"maintenance {token}")["maintenance"] is True
    assert send("status")["state"] == "maintenance"

    reply = send("exit-maintenance")
    assert reply["state"] == "normal"
    assert send("status")["writes_allowed"] is True


def test_compact_over_socket_refused_while_contained(live_socket) -> None:
    send, engine, _priv = live_socket
    engine.write(0, b"EVIDENCE".ljust(BLOCK_SIZE, b"."))
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")

    reply = send("compact")
    assert reply["compacted"] is False
    assert "refused" in reply["error"]
    assert engine.read(0).startswith(b"EVIDENCE")


def test_compact_over_socket_allowed_when_normal(live_socket) -> None:
    send, engine, _priv = live_socket
    engine.write(0, b"KEEP".ljust(BLOCK_SIZE, b"."))

    reply = send("compact")
    assert reply["compacted"] is True
    assert (engine.journal.root / "snapshots" / reply["snapshot_name"]).exists()


def test_exit_maintenance_compact_over_socket(live_socket) -> None:
    send, engine, priv = live_socket
    engine.write(0, b"BEFORE".ljust(BLOCK_SIZE, b"."))

    token = _token(engine, priv, "enter_maintenance")
    send(f"maintenance {token}")
    reply = send("exit-maintenance compact")

    assert reply["state"] == "normal"
    assert "compacted_snapshot" in reply
    assert engine.read(0).startswith(b"BEFORE")


def test_replayed_token_is_refused_over_socket(live_socket) -> None:
    send, engine, priv = live_socket
    token = _token(engine, priv, "enter_maintenance")
    assert send(f"maintenance {token}")["maintenance"] is True
    send("exit-maintenance")
    reply = send(f"maintenance {token}")
    assert reply["maintenance"] is False


def test_socket_survives_a_garbage_request(live_socket) -> None:
    send, _engine, _priv = live_socket
    send("\x00\xff not a command")
    assert send("status")["state"] == "normal"


# ---------------------------------------------------------------------------
# Policy config loading
# ---------------------------------------------------------------------------

def test_load_policy_reads_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"policy": {"alert_threshold": 0.5,
                                               "containment_threshold": 0.7}}))
    config = load_policy(path)
    assert config.alert_threshold == 0.5
    assert config.containment_threshold == 0.7
    assert config.containment_enabled is True


def test_load_policy_can_disable_containment(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"policy": {"containment_enabled": False}}))
    assert load_policy(path).containment_enabled is False


def test_load_policy_rejects_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"policy": {"make_it_faster": True}}))
    with pytest.raises(ValueError, match="unknown policy fields"):
        load_policy(path)


def test_load_policy_accepts_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("")
    assert load_policy(path).containment_enabled is True
