"""Aegis Shield daemon service."""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import threading
from pathlib import Path
from typing import Optional

import uvicorn

from ..api.app import create_app
from ..core import AegisEngine, DurableJournal, Policy, PolicyConfig

log = logging.getLogger("aegis.daemon")


def _provision_if_needed(namespace_dir: Path, blocks: int, block_size: int = 4096) -> DurableJournal:
    if namespace_dir.exists():
        log.info("Opening existing journal at %s", namespace_dir)
        return DurableJournal(namespace_dir)
    log.info("Provisioning new journal at %s (%d blocks)", namespace_dir, blocks)
    return DurableJournal.provision(namespace_dir, blocks=blocks, block_size=block_size)


class AegisDaemon:
    """Main daemon: journal + engine + API server + Unix socket."""

    def __init__(
        self,
        namespace_dir: Path,
        audit_path: Path,
        *,
        host: str = "0.0.0.0",
        port: int = 8443,
        blocks: int = 1024,
        public_key_path: Optional[Path] = None,
        unix_socket_path: Optional[Path] = None,
        policy_config: Optional[PolicyConfig] = None,
    ):
        self.namespace_dir = namespace_dir
        self.audit_path = audit_path
        self.host = host
        self.port = port
        self.blocks = blocks
        self.public_key_path = public_key_path
        self.unix_socket_path = unix_socket_path or Path("/run/aegis-shield/aegis.sock")
        self.policy_config = policy_config or PolicyConfig()
        self._shutdown_event = threading.Event()

    def _setup_signals(self) -> None:
        def _handler(signum, frame):
            log.info("Signal %s received, shutting down", signum)
            self._shutdown_event.set()

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

    def _serve_unix_socket(self, engine: AegisEngine) -> None:
        sock_path = self.unix_socket_path
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        if sock_path.exists():
            sock_path.unlink()

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(sock_path))
            server.listen(5)
            server.settimeout(1.0)
            log.info("Unix socket listening at %s", sock_path)
            while not self._shutdown_event.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    try:
                        data = conn.recv(256).decode("utf-8").strip()
                        if data == "status":
                            response = json.dumps(engine.status())
                        else:
                            response = json.dumps({"error": f"unknown command: {data}"})
                        conn.sendall((response + "\n").encode("utf-8"))
                    except Exception as exc:
                        log.warning("Unix socket error: %s", exc)

    def run(self) -> None:
        self._setup_signals()
        journal = _provision_if_needed(self.namespace_dir, self.blocks)
        policy = Policy(self.policy_config)
        engine = AegisEngine(journal, policy, self.audit_path)
        log.info("Engine started — state=%s device_id=%s", engine.state.value, journal.device_id)

        app = create_app(engine=engine, public_key_path=self.public_key_path)

        sock_thread = threading.Thread(
            target=self._serve_unix_socket,
            args=(engine,),
            daemon=True,
            name="aegis-unix-socket",
        )
        sock_thread.start()

        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="info", access_log=True)
        server = uvicorn.Server(config)

        uvicorn_thread = threading.Thread(target=server.run, name="aegis-uvicorn", daemon=True)
        uvicorn_thread.start()
        log.info("API server started on %s:%d", self.host, self.port)

        self._shutdown_event.wait()
        log.info("Stopping API server")
        server.should_exit = True
        uvicorn_thread.join(timeout=10)
        log.info("Daemon stopped")
