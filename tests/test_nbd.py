"""NBD protocol tests. This module previously had zero test coverage (F-07, F-08)."""

from __future__ import annotations

import errno
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from aegis_shield.core import AegisEngine, DurableJournal, Policy, PolicyConfig
from aegis_shield.core.nbd import (
    NBD_CMD_DISC,
    NBD_CMD_FLUSH,
    NBD_CMD_READ,
    NBD_CMD_WRITE,
    NBD_FLAG_FIXED_NEWSTYLE,
    NBD_FLAG_NO_ZEROES,
    NBD_IHAVEOPT,
    NBD_OPT_EXPORT_NAME,
    NBD_REQUEST_MAGIC,
    serve_tcp,
)

BLOCK_SIZE = 4096


@pytest.fixture()
def server(tmp_path: Path):
    """Start an NBD server on an ephemeral port and yield (port, engine)."""
    journal = DurableJournal.provision(tmp_path / "ns", blocks=16, block_size=BLOCK_SIZE)
    engine = AegisEngine(
        journal, Policy(PolicyConfig(containment_enabled=False)), tmp_path / "audit.jsonl"
    )

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    thread = threading.Thread(
        target=serve_tcp, args=(engine, "127.0.0.1", port, "aegis"), daemon=True
    )
    thread.start()

    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.02)

    yield port, engine, thread


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _connect(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    _recv_exact(sock, 18)                                          # server greeting
    # NO_ZEROES matters: without it the server appends 124 padding bytes after
    # the export reply, and every later read would be off by that much.
    sock.sendall(struct.pack(">I", NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES))
    sock.sendall(struct.pack(">QII", NBD_IHAVEOPT, NBD_OPT_EXPORT_NAME, 5) + b"aegis")
    _recv_exact(sock, 10)                                          # export size + flags
    return sock


def _request(sock: socket.socket, command: int, offset: int, length: int, payload=b"") -> tuple:
    sock.sendall(struct.pack(">IHHQQI", NBD_REQUEST_MAGIC, 0, command, 1, offset, length))
    if payload:
        sock.sendall(payload)
    _magic, error, _handle = struct.unpack(">IIQ", _recv_exact(sock, 16))
    data = b""
    if command == NBD_CMD_READ and error == 0:
        data = _recv_exact(sock, length)
    return error, data


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_write_then_read_roundtrip(server) -> None:
    port, _engine, _thread = server
    sock = _connect(port)
    payload = b"nbd-roundtrip".ljust(BLOCK_SIZE, b".")

    assert _request(sock, NBD_CMD_WRITE, 0, BLOCK_SIZE, payload)[0] == 0
    error, data = _request(sock, NBD_CMD_READ, 0, BLOCK_SIZE)
    assert error == 0 and data == payload
    sock.close()


def test_flush_succeeds(server) -> None:
    port, _engine, _thread = server
    sock = _connect(port)
    assert _request(sock, NBD_CMD_FLUSH, 0, 0)[0] == 0
    sock.close()


def test_unaligned_request_is_einval(server) -> None:
    port, _engine, _thread = server
    sock = _connect(port)
    assert _request(sock, NBD_CMD_READ, 17, BLOCK_SIZE)[0] == errno.EINVAL
    sock.close()


def test_out_of_range_request_is_einval(server) -> None:
    port, _engine, _thread = server
    sock = _connect(port)
    assert _request(sock, NBD_CMD_READ, 999 * BLOCK_SIZE, BLOCK_SIZE)[0] == errno.EINVAL
    sock.close()


def test_write_to_contained_device_is_erofs(server) -> None:
    """Containment must be enforced at the block-device boundary too."""
    port, engine, _thread = server
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")

    sock = _connect(port)
    error, _ = _request(sock, NBD_CMD_WRITE, 0, BLOCK_SIZE, b"\x00" * BLOCK_SIZE)
    assert error == errno.EROFS
    sock.close()


def test_read_still_allowed_when_contained(server) -> None:
    port, engine, _thread = server
    engine.reject_destructive_command(opcode=0xC0, name="format_nvm")

    sock = _connect(port)
    assert _request(sock, NBD_CMD_READ, 0, BLOCK_SIZE)[0] == 0
    sock.close()


# ---------------------------------------------------------------------------
# F-07 — a hostile client must not take the server down
# ---------------------------------------------------------------------------

def test_malformed_magic_does_not_kill_the_server(server) -> None:
    port, _engine, thread = server

    hostile = _connect(port)
    hostile.sendall(struct.pack(">IHHQQI", 0xDEADBEEF, 0, 0, 0, 0, 0))
    time.sleep(0.3)
    hostile.close()
    time.sleep(0.3)

    assert thread.is_alive(), "one bad frame must not kill the NBD server"
    survivor = _connect(port)
    assert _request(survivor, NBD_CMD_READ, 0, BLOCK_SIZE)[0] == 0
    survivor.close()


def test_oversized_write_does_not_kill_the_server(server) -> None:
    port, _engine, thread = server

    hostile = _connect(port)
    hostile.sendall(
        struct.pack(">IHHQQI", NBD_REQUEST_MAGIC, 0, NBD_CMD_WRITE, 1, 0, 64 * 1024 * 1024)
    )
    time.sleep(0.3)
    hostile.close()
    time.sleep(0.3)

    assert thread.is_alive()
    survivor = _connect(port)
    assert _request(survivor, NBD_CMD_READ, 0, BLOCK_SIZE)[0] == 0
    survivor.close()


def test_abrupt_disconnect_does_not_kill_the_server(server) -> None:
    port, _engine, thread = server
    rude = _connect(port)
    rude.close()
    time.sleep(0.2)

    assert thread.is_alive()
    survivor = _connect(port)
    assert _request(survivor, NBD_CMD_READ, 0, BLOCK_SIZE)[0] == 0
    survivor.close()


def test_many_hostile_clients_then_a_good_one(server) -> None:
    port, _engine, thread = server
    for _ in range(15):
        hostile = _connect(port)
        hostile.sendall(struct.pack(">IHHQQI", 0xBADBAD, 0, 0, 0, 0, 0))
        hostile.close()
    time.sleep(0.4)

    assert thread.is_alive()
    survivor = _connect(port)
    assert _request(survivor, NBD_CMD_READ, 0, BLOCK_SIZE)[0] == 0
    survivor.close()


def test_clean_disconnect_command(server) -> None:
    port, _engine, thread = server
    sock = _connect(port)
    sock.sendall(struct.pack(">IHHQQI", NBD_REQUEST_MAGIC, 0, NBD_CMD_DISC, 1, 0, 0))
    sock.close()
    time.sleep(0.2)
    assert thread.is_alive()
