"""Aegis Shield daemon service.

Provisions a journal if needed, starts the engine, serves the FastAPI server,
exposes a Unix socket for CLI status queries and local recovery authorization,
and optionally runs an NBD server so the namespace appears as a block device.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
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
    """Main daemon: journal + engine + API server + Unix socket (+ optional NBD)."""

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
        # NBD — disabled by default; set nbd_host to enable.
        nbd_host: Optional[str] = None,
        nbd_port: int = 10809,
        nbd_export: str = "aegis",
    ):
        self.namespace_dir = namespace_dir
        self.audit_path = audit_path
        self.host = host
        self.port = port
        self.blocks = blocks
        self.public_key_path = public_key_path
        self.unix_socket_path = unix_socket_path or Path("/run/aegis-shield/aegis.sock")
        self.policy_config = policy_config or PolicyConfig()
        self.nbd_host = nbd_host
        self.nbd_port = nbd_port
        self.nbd_export = nbd_export
        self._shutdown_event = threading.Event()

    def _setup_signals(self) -> None:
        def _handler(signum, frame):
            log.info("Signal %s received, shutting down", signum)
            self._shutdown_event.set()

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

    # ── Unix socket ──────────────────────────────────────────────────────────────────

    def _serve_unix_socket(self, engine: AegisEngine) -> None:
        """Serve status queries and local-only recovery authorization.

        Commands
        --------
        status
            Return engine status as JSON.
        authorize <token>
            Attempt recovery authorization with physical_presence=True.
            Physical presence is considered asserted because the caller has
            local shell access (Unix socket is not network-reachable).
        """
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
                        data = conn.recv(4096).decode("utf-8").strip()
                        response = self._handle_socket_command(data, engine)
                        conn.sendall((response + "\n").encode("utf-8"))
                    except Exception as exc:
                        log.warning("Unix socket error: %s", exc)

    def _handle_socket_command(self, command: str, engine: AegisEngine) -> str:
        if command == "status":
            return json.dumps(engine.status())

        if command.startswith("authorize "):
            token = command[len("authorize "):].strip()
            return self._socket_authorize(token, engine)

        return json.dumps({"error": f"unknown command: {command!r}"})

    def _socket_authorize(self, token: str, engine: AegisEngine) -> str:
        """Authorize recovery via the Unix socket — physical presence is asserted."""
        if not self.public_key_path or not self.public_key_path.exists():
            return json.dumps({"error": "no public key configured on this daemon"})
        try:
            from ..core.tokens import TokenVerifier

            verifier = TokenVerifier(self.public_key_path.read_bytes())
            engine.authorize_recovery(
                token,
                verifier,
                physical_presence=True,  # local socket = physical access
            )
            return json.dumps({"authorized": True, "state": engine.state.value})
        except (RuntimeError, PermissionError, ValueError) as exc:
            return json.dumps({"authorized": False, "error": str(exc)})

    # ── NBD server ───────────────────────────────────────────────────────────────────

    def _serve_nbd(self, engine: AegisEngine) -> None:
        """Run the NBD write-gate in a daemon thread (single-connection loop)."""
        from ..core.nbd import serve_tcp

        log.info(
            "NBD server starting on %s:%d export=%r",
            self.nbd_host,
            self.nbd_port,
            self.nbd_export,
        )
        try:
            serve_tcp(engine, self.nbd_host, self.nbd_port, self.nbd_export)
        except Exception as exc:
            log.error("NBD server terminated unexpectedly: %s", exc)

    # ── Main run loop ──────────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._setup_signals()
        journal = _provision_if_needed(self.namespace_dir, self.blocks)
        policy = Policy(self.policy_config)
        engine = AegisEngine(journal, policy, self.audit_path)
        log.info("Engine started — state=%s device_id=%s", engine.state.value, journal.device_id)

        app = create_app(engine=engine, public_key_path=self.public_key_path)

        # Unix socket thread
        sock_thread = threading.Thread(
            target=self._serve_unix_socket,
            args=(engine,),
            daemon=True,
            name="aegis-unix-socket",
        )
        sock_thread.start()

        # NBD thread (optional)
        if self.nbd_host is not None:
            nbd_thread = threading.Thread(
                target=self._serve_nbd,
                args=(engine,),
                daemon=True,
                name="aegis-nbd",
            )
            nbd_thread.start()

        # Uvicorn config
        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="info",
            access_log=True,
        )
        server = uvicorn.Server(config)

        # Run uvicorn in a thread so we can intercept signals ourselves
        uvicorn_thread = threading.Thread(target=server.run, name="aegis-uvicorn", daemon=True)
        uvicorn_thread.start()
        log.info("API server started on %s:%d", self.host, self.port)

        self._shutdown_event.wait()
        log.info("Stopping API server")
        server.should_exit = True
        uvicorn_thread.join(timeout=10)
        log.info("Daemon stopped")
