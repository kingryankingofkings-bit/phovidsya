from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from .audit import AuditLog
from .features import AnalyzerConfig, WindowAnalyzer
from .journal import DurableJournal
from .policy import Policy
from .tokens import TokenVerifier
from .types import AegisState, Decision, IoEvent, IoKind

_STATE_FILENAME = "engine_state.json"

# Audit event that records the digest of every persisted engine state.  On load
# the state file is re-hashed and compared against the most recent such event,
# so tampering with the state file alone is detected: an attacker would also
# have to forge the hash-chained audit log, which ``AuditLog.verify()`` checks.
_STATE_DIGEST_EVENT = "state_persisted"

# Mirrors the hard cap enforced in tokens.TokenVerifier.verify.
_MAX_TOKEN_LIFETIME_SECONDS = 900


def _state_digest(value: dict) -> str:
    """Return the SHA-256 of a state payload in its canonical serialized form."""
    return hashlib.sha256(_state_payload_bytes(value)).hexdigest()


def _state_payload_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def _atomic_write_json(path: Path, value: dict) -> None:
    """Write *value* to *path* atomically (write-temp, fsync, rename)."""
    tmp = path.with_suffix(".json.new")
    payload = _state_payload_bytes(value)
    with tmp.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    # fsync the directory so the rename is durable
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class AegisEngine:
    """Executable storage-semantics model. It is not a PCIe/NVMe transport implementation."""

    def __init__(self, journal: DurableJournal, policy: Policy, audit_path: str | Path):
        self.journal = journal
        self.policy = policy
        self.audit = AuditLog(audit_path)
        self.analyzer = WindowAnalyzer(
            AnalyzerConfig(namespace_blocks=journal.blocks)
        )
        self._state_path = journal.root / _STATE_FILENAME
        # One lock serialises every mutation of engine state.  The daemon drives
        # this object from three concurrent sources (HTTP, Unix socket, NBD), and
        # both hash chains are read-modify-write sequences that a race would break.
        self._lock = threading.RLock()

        self.state = AegisState.BOOT_SELFTEST
        self.state_version = 0
        self.containment_sequence: int | None = None
        self.recovery_sequence: int | None = None
        self._used_nonces: dict[str, int] = {}

        # A journal that discarded an unacknowledged partial record at open must
        # say so in the audit log. Recovery is legitimate, but it is a fact
        # about the device's history and belongs in the forensic record.
        recovered = getattr(journal, "recovered_tail", None)
        if recovered is not None:
            self.audit.append(
                "journal_tail_recovered",
                {
                    "bytes_discarded": recovered.bytes_discarded,
                    "reason": recovered.reason,
                    "preserved_as": recovered.sidecar,
                },
            )

        persisted, load_error = self._load_state()
        if load_error is not None:
            # A state file that exists but cannot be trusted must never be treated
            # as "no state" — that would silently release containment.  Fail closed.
            self._enter_fault(f"engine state could not be trusted: {load_error}")
        elif persisted is not None:
            self.state = AegisState(persisted["state"])
            self.state_version = int(persisted["state_version"])
            self.containment_sequence = persisted.get("containment_sequence")
            self.recovery_sequence = persisted.get("recovery_sequence")
            self._used_nonces = self._prune_nonces(persisted.get("used_nonces", {}))
            self.audit.append(
                "engine_restored",
                {
                    "state": self.state.value,
                    "state_version": self.state_version,
                    "containment_sequence": self.containment_sequence,
                },
            )
        else:
            self._transition(AegisState.NORMAL, "self-test complete")

    # ── Persistence ────────────────────────────────────────────────────────────────────

    def _load_state(self) -> tuple[dict | None, str | None]:
        """Load persisted state.

        Returns ``(state, None)`` when a trustworthy state file was read,
        ``(None, None)`` when there is genuinely no prior state (first boot), and
        ``(None, reason)`` when a state file exists but cannot be trusted.

        The third case must never be confused with the second.  Treating an
        unreadable or tampered state file as a fresh boot would silently return a
        CONTAINED device to NORMAL with writes re-enabled — no token, no nonce,
        no physical presence.  Callers fail closed on a non-``None`` reason.
        """
        if not self._state_path.exists():
            # Genuinely absent state is a first boot only when the audit log has
            # never recorded a persisted state.  If it has, the file was removed.
            recorded = self._recorded_state_digest()
            if recorded is not None:
                return None, "state file is missing but the audit log records one"
            return None, None
        try:
            raw = self._state_path.read_bytes()
            value = json.loads(raw)
            AegisState(value["state"])
            int(value["state_version"])
        except Exception as exc:
            return None, f"state file is unreadable ({type(exc).__name__})"

        recorded = self._recorded_state_digest()
        if recorded is None:
            # A state file with no corresponding audit record cannot be
            # authenticated.  Only accept it if the audit log is itself empty
            # (e.g. an operator moved the namespace without its audit log).
            if self._audit_is_empty():
                return value, None
            return None, "state file has no matching audit record"
        actual = _state_digest(value)
        if actual != recorded:
            return None, "state file digest does not match the audit record"
        return value, None

    def _audit_is_empty(self) -> bool:
        try:
            return self.audit.path.stat().st_size == 0
        except OSError:
            return True

    def _recorded_state_digest(self) -> str | None:
        """Return the digest from the most recent ``state_persisted`` audit event.

        The audit log is hash-chained, so it is verified before being trusted.
        A chain that does not verify yields ``None`` and, combined with a present
        state file, drives the caller into FAULT.
        """
        try:
            self.audit.verify()
        except Exception:
            return None
        digest: str | None = None
        try:
            with self.audit.path.open("rb") as handle:
                for raw in handle:
                    if not raw.strip():
                        continue
                    entry = json.loads(raw)
                    if entry.get("event") == _STATE_DIGEST_EVENT:
                        digest = entry.get("details", {}).get("digest")
        except (OSError, ValueError):
            return None
        return digest

    @staticmethod
    def _prune_nonces(value: object, now: int | None = None) -> dict[str, int]:
        """Drop nonces whose tokens can no longer be valid.

        Tokens carry a hard 15-minute maximum lifetime, so a nonce older than
        that is already unusable and need not be retained.  Accepts the legacy
        list form as well as the current ``{nonce: expires_unix}`` mapping.
        """
        current = int(time.time()) if now is None else now
        if isinstance(value, dict):
            return {n: int(e) for n, e in value.items() if int(e) > current}
        if isinstance(value, list):
            # Legacy format carried no expiry; retain for one maximum token
            # lifetime so an in-flight replay is still rejected after upgrade.
            return {str(n): current + _MAX_TOKEN_LIFETIME_SECONDS for n in value}
        return {}

    def _save_state(self) -> None:
        """Persist engine state and record its digest in the audit log.

        The digest is written *before* the file so that a crash between the two
        leaves an audit record with no matching file — which loads as FAULT
        rather than as an unguarded fresh boot.
        """
        self._used_nonces = self._prune_nonces(self._used_nonces)
        payload = {
            "state": self.state.value,
            "state_version": self.state_version,
            "containment_sequence": self.containment_sequence,
            "recovery_sequence": self.recovery_sequence,
            # {nonce: expires_unix}; entries past expiry are pruned on every save.
            "used_nonces": dict(sorted(self._used_nonces.items())),
        }
        self.audit.append(_STATE_DIGEST_EVENT, {"digest": _state_digest(payload)})
        _atomic_write_json(self._state_path, payload)

    # ── State machine ────────────────────────────────────────────────────────────────────

    def _enter_fault(self, reason: str) -> None:
        """Enter FAULT from any state, denying writes.

        FAULT is the fail-safe sink: it is reachable from everywhere, permits
        reads, forbids writes, and can only be left through an authorized
        maintenance transition.  Unlike :meth:`_transition` it does not consult
        the adjacency table, because the conditions that call it (unreadable
        state, corrupt journal, broken audit chain) can arise in any state.
        """
        previous = self.state
        self.state = AegisState.FAULT
        self.state_version += 1
        self.audit.append(
            "fault_entered",
            {"from": previous.value, "reason": reason, "version": self.state_version},
        )
        self._save_state()

    def _transition(self, target: AegisState, reason: str) -> None:
        allowed = {
            AegisState.BOOT_SELFTEST: {AegisState.NORMAL, AegisState.PROVISIONING, AegisState.FAULT},
            AegisState.PROVISIONING: {AegisState.NORMAL, AegisState.FAULT},
            AegisState.NORMAL: {AegisState.ELEVATED, AegisState.CONTAINED, AegisState.MAINTENANCE, AegisState.FAULT},
            AegisState.ELEVATED: {AegisState.NORMAL, AegisState.CONTAINED, AegisState.FAULT},
            AegisState.CONTAINED: {AegisState.RECOVERY_READ_ONLY, AegisState.MAINTENANCE, AegisState.FAULT},
            AegisState.RECOVERY_READ_ONLY: {AegisState.MAINTENANCE, AegisState.FAULT},
            AegisState.MAINTENANCE: {AegisState.NORMAL, AegisState.FAULT},
            AegisState.FAULT: {AegisState.MAINTENANCE},
        }
        if target not in allowed[self.state]:
            raise RuntimeError(f"illegal transition {self.state.value} -> {target.value}")
        previous = self.state
        self.state = target
        self.state_version += 1
        self.audit.append(
            "state_transition",
            {"from": previous.value, "to": target.value, "reason": reason, "version": self.state_version},
        )
        self._save_state()

    # ── I/O operations ──────────────────────────────────────────────────────────────────

    def read(self, lba: int, blocks: int = 1) -> bytes:
        with self._lock:
            sequence = (
                self.recovery_sequence if self.state is AegisState.RECOVERY_READ_ONLY else None
            )
            event = IoEvent(IoKind.READ, lba, blocks, timestamp_ns=time.time_ns())
            self.analyzer.observe(event)
            return self.journal.read(lba, blocks, at_sequence=sequence)

    def write(self, lba: int, payload: bytes) -> Decision:
        with self._lock:
            if self.state not in (AegisState.NORMAL, AegisState.ELEVATED):
                raise PermissionError(f"writes prohibited in {self.state.value}")
            if len(payload) % self.journal.block_size:
                raise ValueError("payload must be block aligned")
            blocks = len(payload) // self.journal.block_size
            before = self.journal.read(lba, blocks)
            event = IoEvent(IoKind.WRITE, lba, blocks, payload, time.time_ns())
            # Persist first; an acknowledged write is always replayable here.
            final_sequence = self.journal.append(lba, payload)
            features = self.analyzer.observe(event, before=before)
            decision = self.policy.evaluate(features)
            self.audit.append(
                "write_persisted",
                {
                    "lba": lba,
                    "blocks": blocks,
                    "sequence": final_sequence,
                    "decision": decision.to_dict(),
                },
            )
            if decision.contain:
                self.containment_sequence = final_sequence
                self._transition(AegisState.CONTAINED, "policy threshold crossed")
            elif decision.alert and self.state is AegisState.NORMAL:
                self._transition(AegisState.ELEVATED, "policy alert threshold crossed")
            return decision

    def flush(self) -> None:
        with self._lock:
            self.journal.flush()
            self.audit.append("flush_complete", {"sequence": self.journal.last_sequence})

    def reject_destructive_command(self, opcode: int, name: str) -> Decision:
        with self._lock:
            event = IoEvent(IoKind.ADMIN, opcode=opcode, timestamp_ns=time.time_ns())
            features = self.analyzer.observe(event)
            decision = self.policy.evaluate(features)
            self.audit.append("destructive_command_rejected", {"opcode": opcode, "name": name})
            if self.state in (AegisState.NORMAL, AegisState.ELEVATED):
                self.containment_sequence = self.journal.last_sequence
                self._transition(AegisState.CONTAINED, f"rejected {name}")
            return decision

    def authorize_recovery(
        self,
        token: str,
        verifier: TokenVerifier,
        *,
        physical_presence: bool,
        now: int | None = None,
    ) -> None:
        with self._lock:
            if self.state is not AegisState.CONTAINED:
                raise RuntimeError("recovery authorization is valid only while contained")
            if not physical_presence:
                raise PermissionError("physical presence input is not asserted")
            authorization = verifier.verify(
                token,
                device_id=self.journal.device_id,
                action="enter_recovery_read_only",
                state_version=self.state_version,
                now=now,
            )
            if authorization.nonce in self._used_nonces:
                raise ValueError("token nonce already used")
            target = authorization.target_sequence
            if target is None or not 0 <= target <= self.journal.last_sequence:
                raise ValueError("invalid recovery sequence")
            self._used_nonces[authorization.nonce] = int(authorization.expires_unix)
            self.recovery_sequence = target
            # Persist nonces before the state transition so a crash between the
            # two cannot allow replay.
            self._save_state()
            self._transition(
                AegisState.RECOVERY_READ_ONLY, "signed authorization plus physical presence"
            )

    # States that can transition directly to MAINTENANCE.
    _MAINTENANCE_ENTRY_STATES = frozenset(
        {AegisState.NORMAL, AegisState.CONTAINED, AegisState.RECOVERY_READ_ONLY, AegisState.FAULT}
    )

    def enter_maintenance(
        self,
        token: str,
        verifier: TokenVerifier,
        *,
        physical_presence: bool,
        now: int | None = None,
    ) -> None:
        """Transition to MAINTENANCE, re-enabling writes for authorised servicing.

        Requires a signed token with ``action="enter_maintenance"`` and local
        physical presence (asserted via the Unix socket, never over HTTP).
        Valid from the *normal*, *contained*, *recovery_read_only*, and *fault*
        states.  Nonces are single-use to prevent token replay.
        """
        with self._lock:
            if self.state not in self._MAINTENANCE_ENTRY_STATES:
                raise RuntimeError(
                    f"cannot enter maintenance from {self.state.value!r}; "
                    "allowed entry states are: normal, contained, recovery_read_only, fault"
                )
            if not physical_presence:
                raise PermissionError("physical presence is not asserted")
            authorization = verifier.verify(
                token,
                device_id=self.journal.device_id,
                action="enter_maintenance",
                state_version=self.state_version,
                now=now,
            )
            if authorization.nonce in self._used_nonces:
                raise ValueError("token nonce already used")
            self._used_nonces[authorization.nonce] = int(authorization.expires_unix)
            # Persist nonce before the transition to survive a crash between them.
            self._save_state()
            self._transition(AegisState.MAINTENANCE, "maintenance authorized via signed token")

    def exit_maintenance(self, *, compact: bool = False) -> str | None:
        """Return from MAINTENANCE to NORMAL, optionally compacting the journal.

        If *compact* is ``True``, materialises the current logical image into a
        new base image (via :meth:`DurableJournal.compact`) and returns the
        resulting snapshot name.  The snapshot captures the pre-compact state
        for audit and rollback purposes.

        Resets *containment_sequence* and *recovery_sequence* — the device is
        returned to clean normal operation.  Physical presence is enforced by
        requiring this call to originate from the Unix socket.
        """
        with self._lock:
            if self.state is not AegisState.MAINTENANCE:
                raise RuntimeError(
                    f"exit_maintenance called from {self.state.value!r}; must be in maintenance"
                )
            snapshot_name: str | None = None
            if compact:
                snapshot_name = self.compact_journal("pre-maintenance")
            self.containment_sequence = None
            self.recovery_sequence = None
            self._transition(AegisState.NORMAL, "maintenance complete")
            return snapshot_name

    # States in which compaction is safe.  Compaction truncates the journal and
    # resets its sequence counter, which would strand containment_sequence /
    # recovery_sequence and destroy the live forensic record of an incident.
    _COMPACTION_STATES = frozenset({AegisState.NORMAL, AegisState.MAINTENANCE})

    def compact_journal(self, prefix: str = "compact") -> str:
        """Compact the journal, refusing to do so during an incident.

        Compaction materialises the current logical image and resets the journal
        to sequence 0.  Any sequence anchor held by the engine would be left
        dangling, so anchors are cleared here and the operation is refused
        outside NORMAL and MAINTENANCE.
        """
        with self._lock:
            if self.state not in self._COMPACTION_STATES:
                raise RuntimeError(
                    f"compaction refused in {self.state.value!r}; the journal is the "
                    "forensic record of an active incident. Allowed states: "
                    "normal, maintenance"
                )
            snapshot_name = f"{prefix}-{time.time_ns()}"
            self.journal.compact(snapshot_name)
            # The old sequence numbers no longer exist after compaction.
            self.containment_sequence = None
            self.recovery_sequence = None
            self._save_state()
            self.audit.append("journal_compacted", {"snapshot_name": snapshot_name})
            return snapshot_name

    def status(self) -> dict:
        with self._lock:
            return self._status_locked()

    def _status_locked(self) -> dict:
        return {
            "device_id": self.journal.device_id,
            "state": self.state.value,
            "state_version": self.state_version,
            "last_sequence": self.journal.last_sequence,
            "containment_sequence": self.containment_sequence,
            "recovery_sequence": self.recovery_sequence,
            "writes_allowed": self.state in (AegisState.NORMAL, AegisState.ELEVATED),
        }
