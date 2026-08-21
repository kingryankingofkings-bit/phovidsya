from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class RecoveryAuthorization:
    action: str
    device_id: str
    expires_unix: int
    issued_unix: int
    nonce: str
    state_version: int
    target_sequence: int | None = None


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    private = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    Path(public_path).write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def sign_authorization(authorization: RecoveryAuthorization, private_pem: bytes) -> str:
    payload = asdict(authorization)
    encoded = _b64encode(_canonical(payload))
    private = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key")
    signature = _b64encode(private.sign(encoded.encode("ascii")))
    return f"aegis1.{encoded}.{signature}"


class TokenVerifier:
    def __init__(self, public_pem: bytes):
        public = serialization.load_pem_public_key(public_pem)
        if not isinstance(public, Ed25519PublicKey):
            raise TypeError("expected an Ed25519 public key")
        self.public = public

    def verify(
        self,
        token: str,
        *,
        device_id: str,
        action: str,
        state_version: int,
        now: int | None = None,
    ) -> RecoveryAuthorization:
        try:
            prefix, encoded, signature = token.split(".")
            if prefix != "aegis1":
                raise ValueError("unsupported token version")
            self.public.verify(_b64decode(signature), encoded.encode("ascii"))
            authorization = RecoveryAuthorization(**json.loads(_b64decode(encoded)))
        except (ValueError, TypeError, KeyError, InvalidSignature, json.JSONDecodeError) as exc:
            raise ValueError("invalid signed authorization") from exc
        current = int(time.time()) if now is None else now
        if authorization.device_id != device_id:
            raise ValueError("token is for another device")
        if authorization.action != action:
            raise ValueError("token action mismatch")
        if authorization.state_version != state_version:
            raise ValueError("token state version is stale")
        if authorization.issued_unix > current + 60:
            raise ValueError("token issued in the future")
        if authorization.expires_unix < current:
            raise ValueError("token expired")
        if authorization.expires_unix - authorization.issued_unix > 900:
            raise ValueError("token lifetime exceeds 15-minute limit")
        return authorization
