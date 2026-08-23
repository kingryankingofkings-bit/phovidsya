# Aegis Shield

**Hardware-grade ransomware isolation — software reference deployment**

Aegis Shield detects ransomware by watching the I/O fingerprint at the storage layer. It does not scan files or signatures. Instead, it models write entropy, overwrite patterns, LBA coverage, and destructive NVMe commands — and when those signals cross a threshold, it freezes the storage namespace in a forensically intact state that can be recovered with a signed token plus physical presence.

This repository is the software reference deployment: the same state machine, the same detection logic, the same audit trail — running on commodity hardware as a Python daemon with a Rust OS-native contract layer.

---

## Architecture overview

```
[ ransomware ]                  [ legitimate app ]
      ↓ writes                         ↓ writes
  ┌──────────────────────────────────────────┐
  │        Aegis Shield engine               │
  │  • Rolling window feature extraction     │
  │  • Weighted policy scoring               │
  │  • NORMAL → ELEVATED → CONTAINED FSM    │
  │  • Signed recovery authorization         │
  └──────────────────────────────────────────┘
      ↓ fsync'd journal            ↓ audit log
  /var/lib/aegis-shield/        audit.jsonl
  namespace/                    (hash-chained)
```

The hardware vision layers an FPGA PCIe interposer between the NVMe SSD and the host, enforcing containment in silicon. This software deployment enforces the same state machine in Python — writes are blocked at the library boundary rather than on the PCIe bus. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a full comparison.

---

## Quick start

```bash
pip install -e ".[dev]"

# Generate admin keys (keep the private key offline)
aegis-shield keygen admin_private.pem admin_public.pem

# Provision a 4 MiB test namespace
aegis-shield provision ./namespace --blocks 1024

# Start the daemon (generates a random API key if AEGIS_API_KEY is not set)
aegis-shield start ./namespace --port 8443 --public-key admin_public.pem
```

Open [http://localhost:8443/ui](http://localhost:8443/ui) for the dashboard
(`/` redirects there).

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for a full walkthrough.

---

## Installation

### pip (development)
```bash
pip install -e .
```

### Docker
```bash
export AEGIS_API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
docker compose -f deploy/docker/docker-compose.yml up -d
```

### systemd (production)

Generate the keypair on a **separate, offline machine** and copy only the public
half to the host. The installer refuses to run if it finds a private key beside
it — a recovery key readable by the daemon can be used to release containment by
anything that compromises the daemon.

```bash
# On an offline machine:
aegis-shield keygen admin.pem admin.pub
scp admin.pub root@<host>:/etc/aegis-shield/admin.pub

# On the protected host:
sudo bash deploy/install.sh          # generates a stable API key in /etc/aegis-shield/env
sudo systemctl enable --now aegis-shield
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for full instructions.

---

## CLI reference

```
aegis-shield provision <namespace-dir> --blocks <n>
    Provision a new file-backed virtual storage namespace.

aegis-shield start <namespace-dir> [--host 0.0.0.0] [--port 8443] [--public-key <pem>]
    Start the daemon and REST API server.

aegis-shield status <namespace-dir>
    Show current engine status.

aegis-shield keygen <private.pem> <public.pem>
    Generate an Ed25519 admin keypair.

aegis-shield issue-token <namespace-dir> <private.pem> --state-version <n>
                         [--action enter_recovery_read_only|enter_maintenance]
    Issue a signed authorization token. Redeem it over the Unix socket:
      echo "authorize   <token>" | nc -U /run/aegis-shield/aegis.sock
      echo "maintenance <token>" | nc -U /run/aegis-shield/aegis.sock

aegis-shield generate-trace <output.jsonl> --pattern <name>
    Generate a synthetic I/O trace for testing.

aegis-shield replay <namespace-dir> <trace.jsonl>
    Replay a trace against a provisioned namespace.

aegis-shield benchmark [--seeds N] [--policy-config <yaml>]
    Measure the policy against the synthetic workload corpus and report
    false positives, true positives, and containment headroom.
```

---

## REST API

Interactive docs: [http://localhost:8443/docs](http://localhost:8443/docs)

| Method | Path | Description |
|---|---|---|
| GET | /v1/health | Unauthenticated health probe |
| GET | /v1/status | Device state, identity, journal capacity |
| GET | /v1/events | Paginated signed audit events |
| POST | /v1/challenge | Issue a one-time recovery challenge |
| POST | /v1/authorize | Submit signed recovery token |
| POST | /v1/recovery/export | Create a point-in-time snapshot |
| GET | /v1/sizing | Storage sizing calculations |

See [docs/API.md](docs/API.md) for the full reference.

---

## Tests

```bash
pytest tests/ -v
```

## Measuring detection

```bash
aegis-shield benchmark
```

Scores 7 benign and 4 ransomware-shaped synthetic workloads through the real
policy and reports the margin between them. Synthetic corpus only — see
[docs/DETECTION.md](docs/DETECTION.md) for what it can and cannot establish.

---

## Capability statement

This software reference deployment is **not** a production-certified security product. Specifically:

- **Enforcement is software-only**: a privileged process on the same host can bypass it. Hardware enforcement requires the FPGA PCIe interposer described in `Aegis-Block/docs/`.
- **Detection coefficients are measured against a synthetic corpus, not real ransomware.** `aegis-shield benchmark` reports 0% false positives on 7 benign workloads and 75% true positives on 4 ransomware-shaped ones, with 0.113 of headroom before a legitimate high-entropy workload would trigger containment. That is a real measurement of I/O *shape*, and it says nothing about efficacy against real malware. Evasion is cheap: one benign write interleaved per encryption escapes containment (though it still raises an alert), and a bigger detection window measurably does not fix that. See [docs/DETECTION.md](docs/DETECTION.md).
- **No TLS out of the box**: use a reverse proxy (nginx, Caddy) in production.
- **Physical presence is local shell access**, asserted by reaching the daemon over its Unix socket. Wire it to a real physical input in production deployments.
- **The Rust crates are specifications, not a runtime layer**: they compile and self-test, but the Python daemon does not call them. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **The NBD export is unauthenticated**: it binds to loopback unless you pass `--nbd-allow-remote`. Anyone who can reach the port has full read/write access.

What it genuinely provides:
- A faithful model of the hardware state machine that can be integrated, tested, and evaluated.
- A forensically intact, hash-chained audit log that is fsync'd after every event.
- A file-backed journal that supports point-in-time recovery snapshots, holding payloads on disk rather than in RAM (~213 B resident per write).
- Crash recovery that survives a power cut without losing the ability to tell a torn write from tampering: an unacknowledged partial record at the tail is discarded, preserved to a sidecar, and audited; anything else refuses to open.
- A signed, short-lived, state-version-bound recovery token scheme with single-use nonces.
- A detection policy weighted toward behaviour over content, because content cannot carry the decision: a compressed archive and an encrypted file are both ~8 bits/byte. What separates them is reading existing data and replacing it in place.
- Containment that fails closed: if the persisted engine state is missing, unreadable, or does not match its digest in the audit chain, the engine enters `fault` with writes denied rather than booting into `normal`.

---

## Third-party components

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

**Proprietary — All Rights Reserved.**

Copyright (c) 2024-2026 Ryan Stephens. Ryan Stephens is the sole owner of the
original project code and documentation in this repository. No permission is
granted to use, copy, modify, distribute, sublicense, sell, commercialize, or
create derivative works without prior express written authorization from Ryan
Stephens. Separately identified third-party dependencies remain subject to
their respective licenses.

See the [Ryan Stephens Proprietary Software License](LICENSE) for the complete
terms.

Original packages (`Aegis-Block`, `Aegis_Shield_OS_Native_Build`) are by the same author.
