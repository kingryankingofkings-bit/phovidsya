# Aegis Shield — Deployment Guide

> **Capability notice**: This is a software reference implementation. It provides the same detection logic, state machine, and audit trail as the hardware architecture — but without hardware enforcement.

## Option A: Docker

```bash
export AEGIS_API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
docker compose -f deploy/docker/docker-compose.yml up -d
```

The container exposes port `8443`.

## Option B: systemd (bare metal)

```bash
sudo bash deploy/install.sh
sudo systemctl enable --now aegis-shield
```

### View logs

```bash
journalctl -u aegis-shield -f
```

## Option C: Development

See [QUICKSTART.md](QUICKSTART.md).

## Security considerations

| Concern | Recommendation |
|---|---|
| API key | `deploy/install.sh` writes one to `/etc/aegis-shield/env` (mode 0640, root-owned). Rotate periodically. |
| Admin private key | Generate offline. The installer **refuses to run** if it finds one in `/etc/aegis-shield`. Anything that can read it can release containment. |
| TLS | Put a reverse proxy (nginx, Caddy) in front of port 8443. Docker binds to loopback for this reason. |
| Physical presence | Currently local Unix-socket access. Wire to a physical button or tamper-evident signal for production. |
| NBD export | Unauthenticated. Loopback-only unless `--nbd-allow-remote` is passed. |
| Namespace backup | Periodically call `POST /v1/recovery/export`. Snapshots are capped at 32; prune old ones. |
| Containment | On by default. Startup warns if a policy file disables it. |

## Recovering from FAULT

The engine enters `fault` — reads allowed, writes denied — when its persisted
state cannot be trusted (file missing, corrupt, or not matching its digest in
the audit chain). This is deliberate: the alternative is silently releasing
containment.

Investigate first. `journalctl -u aegis-shield` will name the reason, and the
audit log records a `fault_entered` event. Once you have established the cause,
return the device to service with a maintenance token:

```bash
TOKEN=$(aegis-shield issue-token /var/lib/aegis-shield/namespace admin.pem \
    --state-version <current> --action enter_maintenance)
echo "maintenance $TOKEN" | nc -U /run/aegis-shield/aegis.sock
echo "exit-maintenance"   | nc -U /run/aegis-shield/aegis.sock
```

## After an unclean shutdown

The daemon recovers automatically. If the crash interrupted a write, the
incomplete record is discarded and the removed bytes are preserved as
`journal.jsonl.torn-<offset>` inside the namespace directory. Check for it:

```bash
ls /var/lib/aegis-shield/namespace/journal.jsonl.torn-*
journalctl -u aegis-shield | grep journal_tail_recovered
```

The audit log records how many bytes were dropped and why. The discarded record
was never acknowledged to the writing application, so no completed write is
lost — but the sidecar is kept for inspection rather than deleted.

If the daemon instead **refuses to start** with a `JournalCorruptionError`, the
damage is not a torn tail: something altered a record that had already been
committed. Treat that as a potential attack on the evidence. Do not delete the
journal — take a copy of the whole namespace directory first.

## Uninstall

```bash
sudo systemctl disable --now aegis-shield
sudo rm /etc/systemd/system/aegis-shield.service && sudo systemctl daemon-reload
sudo pip3 uninstall aegis-shield
# Namespace and keys are left in place deliberately — they hold your data and
# your recovery material. Remove them only when you are certain:
#   sudo rm -rf /var/lib/aegis-shield /etc/aegis-shield
```
