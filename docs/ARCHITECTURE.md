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
├───────────────────────────────────────────────────────────┤
│  crates/ (Rust, no_std)  OS-native security contracts   │
│  ├─ storage-guardian-contract                          │
│  ├─ storage-transaction-core                           │
│  ├─ dma-command-ir                                     │
│  └─ authority-membrane-contract                        │
│  kernel/guardian-monitor  Pre-kernel mediation          │
└───────────────────────────────────────────────────────────┘
```

## State machine

| State | Writes | Reads | Trigger |
|-------|--------|-------|---------|
| `normal` | ✓ | ✓ | Default after boot |
| `elevated` | ✓ | ✓ | Score ≥ alert_threshold |
| `contained` | ✗ | ✓ | Score ≥ containment_threshold, or destructive command |
| `recovery_read_only` | ✗ | ✓ (at snapshot) | Signed token + physical presence |
| `maintenance` | ✓ | ✓ | Authorized reset |

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

Alert threshold: 0.65 (containment disabled by default).
Containment threshold: 0.82 (requires `containment_enabled=True`).

## Recovery token format

```
aegis1.<base64url(canonical-json)>.<base64url(ed25519-signature)>
```

Binds: `action`, `device_id`, `state_version`, `target_sequence`, `nonce`, `issued_unix`, `expires_unix`.
Nonces are single-use. Maximum TTL: 15 minutes.
