from __future__ import annotations

import time
from pathlib import Path

from .audit import AuditLog
from .features import AnalyzerConfig, WindowAnalyzer
from .journal import DurableJournal
from .policy import Policy
from .tokens import TokenVerifier
from .types import AegisState, Decision, IoEvent, IoKind


class AegisEngine:
    """Executable storage-semantics model. It is not a PCIe/NVMe transport implementation."""

    def __init__(self, journal: DurableJournal, policy: Policy, audit_path: str | Path):
        self.journal = journal
        self.policy = policy
        self.audit = AuditLog(audit_path)
        self.analyzer = WindowAnalyzer(
            AnalyzerConfig(namespace_blocks=journal.blocks)
        )
        self.state = AegisState.BOOT_SELFTEST
        self.state_version = 0
        self.containment_sequence: int | None = None
        self.recovery_sequence: int | None = None
        self._used_nonces: set[str] = set()
        self._transition(AegisState.NORMAL, "self-test complete")

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
        self._transition(AegisState.RECOVERY_READ_ONLY, "signed authorization plus physical presence")

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
