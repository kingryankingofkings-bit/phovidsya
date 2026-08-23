from __future__ import annotations

import errno
import logging
import socket
import struct
from dataclasses import dataclass

from .engine import AegisEngine

log = logging.getLogger("aegis.nbd")

NBD_MAGIC = 0x4E42444D41474943
NBD_IHAVEOPT = 0x49484156454F5054
NBD_REQUEST_MAGIC = 0x25609513
NBD_REPLY_MAGIC = 0x67446698
NBD_FLAG_FIXED_NEWSTYLE = 1 << 0
NBD_FLAG_NO_ZEROES = 1 << 1
NBD_FLAG_HAS_FLAGS = 1 << 0
NBD_FLAG_SEND_FLUSH = 1 << 2
NBD_OPT_EXPORT_NAME = 1
NBD_CMD_READ = 0
NBD_CMD_WRITE = 1
NBD_CMD_DISC = 2
NBD_CMD_FLUSH = 3


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise ConnectionError("peer closed connection")
        value.extend(chunk)
    return bytes(value)


@dataclass
class NbdServer:
    """Minimal fixed-newstyle NBD export for an isolated lab network.

    It intentionally supports one export and READ/WRITE/FLUSH only. There is no TLS,
    multi-connection, structured reply, TRIM, resize, or production hardening.
    """

    engine: AegisEngine
    export_name: bytes = b"aegis"

    @property
    def export_size(self) -> int:
        return self.engine.journal.blocks * self.engine.journal.block_size

    def negotiate(self, connection: socket.socket) -> None:
        connection.sendall(
            struct.pack(">QQH", NBD_MAGIC, NBD_IHAVEOPT, NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES)
        )
        client_flags = struct.unpack(">I", _recv_exact(connection, 4))[0]
        if not client_flags & NBD_FLAG_FIXED_NEWSTYLE:
            raise ValueError("client does not support fixed newstyle negotiation")
        magic, option, length = struct.unpack(">QII", _recv_exact(connection, 16))
        if magic != NBD_IHAVEOPT or option != NBD_OPT_EXPORT_NAME or length > 4096:
            raise ValueError("only NBD_OPT_EXPORT_NAME is supported")
        requested_name = _recv_exact(connection, length)
        if requested_name not in (b"", self.export_name):
            raise ValueError("unknown export name")
        connection.sendall(
            struct.pack(">QH", self.export_size, NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH)
        )
        if not client_flags & NBD_FLAG_NO_ZEROES:
            connection.sendall(bytes(124))

    def transmit(self, connection: socket.socket) -> None:
        block_size = self.engine.journal.block_size
        while True:
            try:
                request = _recv_exact(connection, 28)
            except ConnectionError:
                return
            magic, flags, command, handle, offset, length = struct.unpack(">IHHQQI", request)
            del flags
            if magic != NBD_REQUEST_MAGIC:
                # The stream is desynchronised; end this connection only.
                raise ConnectionError("bad NBD request magic")
            if command == NBD_CMD_DISC:
                return
            error = 0
            result = b""
            payload = b""
            if command == NBD_CMD_WRITE:
                if length > 16 * 1024 * 1024:
                    # Cannot safely resynchronise the stream past an oversized
                    # payload, so drop this connection — never the server.
                    raise ConnectionError("NBD request exceeds 16 MiB reference limit")
                payload = _recv_exact(connection, length)
            if command == NBD_CMD_FLUSH:
                if offset != 0 or length != 0:
                    error = errno.EINVAL
                else:
                    try:
                        self.engine.flush()
                    except OSError:
                        error = errno.EIO
            elif offset % block_size or length == 0 or length % block_size or offset + length > self.export_size:
                error = errno.EINVAL
            else:
                lba = offset // block_size
                blocks = length // block_size
                try:
                    if command == NBD_CMD_READ:
                        result = self.engine.read(lba, blocks)
                    elif command == NBD_CMD_WRITE:
                        self.engine.write(lba, payload)
                    else:
                        error = errno.EOPNOTSUPP
                except PermissionError:
                    error = errno.EROFS
                except (ValueError, OSError):
                    error = errno.EIO
            connection.sendall(struct.pack(">IIQ", NBD_REPLY_MAGIC, error, handle) + result)

    def serve_connection(self, connection: socket.socket) -> None:
        self.negotiate(connection)
        self.transmit(connection)


def serve_tcp(engine: AegisEngine, host: str, port: int, export_name: str = "aegis") -> None:
    """Serve NBD until the process ends.

    A misbehaving or malicious client must never take the export down for
    everyone: every per-connection failure is contained, logged, and followed by
    another ``accept()``.  Only a failure of the listening socket itself stops
    the loop.
    """
    server = NbdServer(engine, export_name.encode("utf-8"))
    with socket.create_server((host, port), reuse_port=False) as listener:
        while True:
            try:
                connection, address = listener.accept()
            except OSError:
                log.error("NBD listener failed; stopping accept loop")
                raise
            try:
                with connection:
                    server.serve_connection(connection)
            except Exception as exc:  # noqa: BLE001 - one client must not kill the server
                log.warning("NBD connection from %s ended: %s", address, exc)
