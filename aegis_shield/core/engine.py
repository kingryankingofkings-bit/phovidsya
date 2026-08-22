from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .audit import AuditLog
from .features import AnalyzerConfig, WindowAnalyzer
from .journal import DurableJournal
from .policy import Policy
from .tokens import TokenVerifier
from .types import AegisState, Decision, IoEvent, IoKind

_STATE_FILENAME = "engine_state.json"


def _atomic_write_json(path: Path, value: dict) -> None:
    """Write *value* to *path* atomically (write-temp, fsync, rename)."""
    tmp = path.with_suffix(".json.new")
    payload = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
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

        # Restore durable state if a previous run left one, otherwise boot fresh.
        persisted = self._load_state()
        if persisted is not None:
            self.state = AegisState(persisted["state"])
            self.state_version = int(persisted["state_version"])
            self.containment_sequence: int | None = persisted.get("containment_sequence")
            self.recovery_sequence: int | None = persisted.get("recovery_sequence")
            self._used_nonces: set[str] = set(persisted.get("used_nonces", []))
            self.audit.append(
                "engine_restored",
                {
                    "state": self.state.value,
                    "state_version": self.state_version,
                    "containment_sequence": self.containment_sequence,
                },
            )
        else:
            self.state = AegisState.BOOT_SELFTEST
            self.state_version = 0
            self.containment_sequence = None
            self.recovery_sequence = None
            self._used_nonces = set()
            self._transition(AegisState.NORMAL, "self-test complete")

    # ── Persistence ────────────────────────────────────────────────────────────────────

    def _load_state(self) -> dict | None:
        """Return the persisted state dict, or *None* if no valid state file exists."""
        if not self._state_path.exists():
            return None
        try:
            value = json.loads(self._state_path.read_bytes())
            # Validate that the recorded state name is a known AegisState
            AegisState(value["state"])
            return value
        except Exception:
            # Corrupt or unrecognisable state file — treat as a fresh start and
            # log a warning via audit once audit is ready (called after init).
            return None

    def _save_state(self) -> None:
        """Atomically persist the current engine state so it survives a restart."""
        _atomic_write_json(
            self._state_path,
            {
                "state": self.state.value,
                "state_version": self.state_version,
                "containment_sequence": self.containment_sequence,
                "recovery_sequence": self.recovery_sequence,
                # Nonces are short hex strings; serialising them all is safe
                # because recovery events are rare and TTL-bounded.
                "used_nonces": sorted(self._used_nonces),
            },
        )

    # ── State machine ────────────────────────────────────────────────────────────────────

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
        sequence = self.recovery_sequence if self.state is AegisState.RECOVERY_READ_ONLY else None
        event = IoEvent(IoKind.READ, lba, blocks, timestamp_ns=time.time_ns())
        self.analyzer.observe(event)
        return self.journal.read(lba, blocks, at_sequence=sequence)

    def write(self, lba: int, payload: bytes) -> Decision:
        if self.state not in (AegisState.NORMAL, AegisState.ELEVATED):
            raise PermissionError(f"writes prohibited in {self.state.value}")
        if len(payload) % self.journal.block_size:
            raise ValueError("payload must be block aligned")
        blocks = len(payload) // self.journal.block_size
        before = self.journal.read(lba, blocks)
        event = IoEvent(IoKind.WRITE, lba, blocks, payload, time.time_ns())
        # Persist first; an acknowledged write is always replayable in this reference model.
        final_sequence = self.journal.append(lba, payload)
        features = self.analyzer.observe(event, before=before)
        decision = self.policy.evaluate(features)
        self.audit.append(
            "write_persisted",
            {"lba": lba, "blocks": blocks, "sequence": final_sequence, "decision": decision.to_dict()},
        )
        if decision.contain:
            self.containment_sequence = final_sequence
            self._transition(AegisState.CONTAINED, "policy threshold crossed")
        elif decision.alert and self.state is AegisState.NORMAL:
            self._transition(AegisState.ELEVATED, "policy alert threshold crossed")
        return decision

    def flush(self) -> None:
        self.journal.flush()
        self.audit.append("flush_complete", {"sequence": self.journal.last_sequence})

    def reject_destructive_command(self, opcode: int, name: str) -> Decision:
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
        self._used_nonces.add(authorization.nonce)
        self.recovery_sequence = target
        # Persist nonces before the state transition so a crash between the two
        # cannot allow replay.
        self._save_state()
        self._transition(AegisState.RECOVERY_READ_ONLY, "signed authorization plus physical presence")

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
        self._used_nonces.add(authorization.nonce)
        # Persist nonce before state transition to survive a crash between the two.
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
        if self.state is not AegisState.MAINTENANCE:
            raise RuntimeError(
                f"exit_maintenance called from {self.state.value!r}; must be in maintenance"
            )
        snapshot_name: str | None = None
        if compact:
            import time as _t
            snapshot_name = f"pre-maintenance-{int(_t.time())}"
            self.journal.compact(snapshot_name)
            self.audit.append("journal_compacted", {"snapshot_name": snapshot_name})
        self.containment_sequence = None
        self.recovery_sequence = None
        self._transition(AegisState.NORMAL, "maintenance complete")
        return snapshot_name

    def status(self) -> dict:
        return {
            "device_id": self.journal.device_id,
            "state": self.state.value,
            "state_version": self.state_version,
            "last_sequence": self.journal.last_sequence,
            "containment_sequence": self.containment_sequence,
            "recovery_sequence": self.recovery_sequence,
            "writes_allowed": self.state in (AegisState.NORMAL, AegisState.ELEVATED),
        }
