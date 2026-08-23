# Architecture — Aegis Shield

## Software layers

```
┌───────────────────────────────────────────────────────────┐
│  aegis_shield.cli        Click CLI (provision, start…)  │
├───────────────────────────────────────────────────────────┤
│  aegis_shield.api        FastAPI REST (v1/*)            │
│  aegis_shield.daemon     AegisDaemon service            │
├───────────────────────────────────────────────────────────┤
│  aegis_shield.core       Storage-semantics model        │
│  ├─ AegisEngine          State machine + write gate     │
│  ├─ DurableJournal       fsync append log + overlay     │
│  ├─ WindowAnalyzer       Transparent feature extractor  │
│  ├─ Policy               Weighted threshold evaluator   │
│  ├─ AuditLog             Hash-chained event log         │
│  └─ TokenVerifier        Ed25519 recovery token check   │
└───────────────────────────────────────────────────────────┘
```

## Rust contract crates — specifications, not a runtime layer

```
crates/ (Rust, no_std)      OS-native security contracts
├─ storage-guardian-contract    mutation / containment / recovery predicates
├─ storage-transaction-core     transactional object + namespace core
├─ dma-command-ir               typed DMA command IR and validator
└─ authority-membrane-contract  untrusted-data-to-authority admission
kernel/guardian-monitor         authority + device mediation predicate
```

**These crates are not linked into the running system.** The Python daemon does
not call them: there is no FFI boundary, no `cdylib`, and no `ctypes`/`pyo3`
binding anywhere in this repository. They are executable *specifications* of the
security contracts the hardware design must satisfy — they compile, they are
`#![no_std]`, they carry their own test suites, and CI enforces `clippy -D
warnings` and `rustfmt` on them.

Read them as the formal statement of intended hardware behaviour, and treat
their bounds literally: `storage-transaction-core`, for example, addresses
`MAX_OBJECTS × MAX_OBJECT_BYTES` = 1 KiB and states in its own module docs that
it stops before any block driver, filesystem mount, sector write, DMA, or
power-loss claim. `kernel/guardian-monitor` is an admission predicate, not a
bootloader or a kernel.

Wiring these contracts into the Python runtime over FFI is future work and is
not represented anywhere in the current implementation.

## State machine

| State | Writes | Reads | Trigger |
|-------|--------|-------|---------|
| `normal` | ✓ | ✓ | Default after boot |
| `elevated` | ✓ | ✓ | Score ≥ alert_threshold |
| `contained` | ✗ | ✓ | Score ≥ containment_threshold, or destructive command |
| `recovery_read_only` | ✗ | ✓ (at snapshot) | Signed token + physical presence |
| `maintenance` | ✓ | ✓ | Signed `enter_maintenance` token + physical presence |
| `fault` | ✗ | ✓ | Untrusted engine state, corrupt journal, or broken audit chain |

## Feature extraction

| Feature | Ransomware signal |
|---------|-------------------|
| `mean_write_entropy` | Encrypted content near 8 bits/byte |
| `high_entropy_write_fraction` | ↑ with encryption |
| `overwrite_fraction` | Ransomware overwrites existing files |
| `changed_byte_fraction` | High for encryption |
| `namespace_coverage_fraction` | Broad campaigns |
| `read_before_write_fraction` | File-replace pattern |
| `deallocate_fraction` | Secure wipe after encrypt |
| `destructive_command_seen` | Format NVM, Sanitize — immediate containment |

## Policy

Default: weighted linear combination, `score = Σ(weight_i × feature_i) / Σ weight_i`.

Alert threshold: 0.65 — raises `elevated`.
Containment threshold: 0.82 — freezes the namespace. **Enabled by default**
(`containment_enabled=True`); set it to `false` in a policy file to run in
detect-only mode, and the daemon will warn at startup that it is off.

The 0.82 threshold sits well above the ~0.65 that sustained maximum-entropy
writes alone produce, so containment requires several corroborating signals
rather than entropy in isolation. These coefficients remain engineering
estimates — they have not been validated against a production ransomware
corpus.

## Recovery token format

```
aegis1.<base64url(canonical-json)>.<base64url(ed25519-signature)>
```

Binds: `action`, `device_id`, `state_version`, `target_sequence`, `nonce`, `issued_unix`, `expires_unix`.
Nonces are single-use and are persisted before the state transition, so a crash
between the two cannot enable replay. Nonces past expiry are pruned on every
save. Maximum TTL: 15 minutes.

Two actions are defined: `enter_recovery_read_only` (forensic reads at a target
sequence) and `enter_maintenance` (re-enable writes for servicing). Issue either
with `aegis-shield issue-token --action <action>`. Both are redeemed over the
Unix socket only — never over HTTP.

## Engine state integrity

`engine_state.json` records the current state, version, sequence anchors, and
used nonces. Every save also appends a `state_persisted` audit event carrying
the SHA-256 of the state payload.

On load the engine re-hashes the file and compares it against the most recent
such event in the hash-chained audit log. A state file that is missing,
unreadable, unmatched by an audit record, or whose digest does not match causes
the engine to **enter FAULT** — writes denied — rather than boot fresh into
`normal`. Releasing containment therefore requires forging both the state file
and the audit chain, and the audit chain is verified before it is trusted.
