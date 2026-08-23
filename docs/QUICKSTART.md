# Aegis Shield — Quick Start (5 minutes)

This guide gets the reference daemon running on a Linux machine.

## Prerequisites

- Python 3.11+
- pip
- A Unix-like OS (Linux recommended; macOS works for development)

## 1. Install

```bash
git clone https://github.com/kingryankingofkings-bit/phovidsya.git
cd phovidsya
pip install -e ".[dev]"
```

## 2. Generate admin keys

```bash
aegis-shield keygen admin_private.pem admin_public.pem
```

## 3. Provision a namespace

```bash
aegis-shield provision ./my-namespace --blocks 1024
```

## 4. Start the daemon

```bash
export AEGIS_API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
aegis-shield start ./my-namespace --port 8443 --public-key admin_public.pem
```

## 5. Open the dashboard

Navigate to [http://localhost:8443/ui](http://localhost:8443/ui). Enter your API key and click **Connect**.

## 6. Try a replay

```bash
aegis-shield generate-trace ./trace.jsonl --pattern high_entropy_append --blocks 1024 --operations 128
aegis-shield provision ./test-ns --blocks 1024
aegis-shield replay ./test-ns ./trace.jsonl
```

## 7. Issue a recovery token (optional)

If the engine is in CONTAINED state:

```bash
TOKEN=$(aegis-shield issue-token ./my-namespace admin_private.pem \
    --state-version 3 --target-sequence 42)
```

Redeem it over the Unix socket — physical presence means local access, so this
cannot be done over HTTP:

```bash
echo "authorize $TOKEN" | nc -U /run/aegis-shield/aegis.sock
```

`POST /v1/authorize` will only tell you whether a token is *valid*; it never
changes state.

## 8. Servicing a contained device

To re-enable writes for maintenance:

```bash
TOKEN=$(aegis-shield issue-token ./my-namespace admin_private.pem \
    --state-version <current> --action enter_maintenance)
echo "maintenance $TOKEN"        | nc -U /run/aegis-shield/aegis.sock
echo "exit-maintenance compact"  | nc -U /run/aegis-shield/aegis.sock
```

`--state-version` must match the engine's current value — read it from
`aegis-shield status ./my-namespace`.

## Next steps

- [DEPLOYMENT.md](DEPLOYMENT.md) — Docker and systemd production deployment
- [API.md](API.md) — Full REST API reference
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture
