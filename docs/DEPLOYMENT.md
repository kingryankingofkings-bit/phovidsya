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
| API key | Use `secrets.token_hex(32)`. Rotate periodically. |
| Admin private key | Generate offline, never deploy to the protected host. |
| TLS | Put a reverse proxy (nginx, Caddy) in front of port 8443. |
| Physical presence | Wire to a physical button or tamper-evident hardware signal. |
| Namespace backup | Periodically call `POST /v1/recovery/export`. |
