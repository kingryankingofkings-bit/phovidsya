# Aegis Shield — REST API Reference

Base URL: `http://<host>:<port>` (default port 8443)

Interactive docs: `/docs` (Swagger) and `/redoc`.

## Authentication

All endpoints except `/v1/health` require `X-API-Key` header.

Set key via `AEGIS_API_KEY` env var.

## Endpoints

### GET /v1/health
Unauthenticated health probe.

### GET /v1/status
Device identity, state, journal capacity.

### GET /v1/events?after=0&limit=100
Paginated hash-chained audit events.

### POST /v1/challenge
Issue a one-time challenge nonce.
Body: `{"action": "enter_recovery_read_only"}` — `action` must be
`enter_recovery_read_only` or `enter_maintenance`; anything else returns 400.

### POST /v1/authorize
Body: `{"challenge_id": "...", "token": "aegis1..."}`

**This endpoint only validates a token. It does not complete recovery.** It
checks the signature, device binding, action, state version, and expiry, and
returns `{"token_valid": true|false}`. No state transition occurs.

There is deliberately no `physical_presence` field: a boolean supplied over the
network cannot represent a physical property. Complete recovery locally:

```bash
echo "authorize <token>" | nc -U /run/aegis-shield/aegis.sock
```

The Unix socket is reachable only from a local shell, and that access is what
stands in for a hardware presence signal in this software deployment.

### POST /v1/recovery/export
Create a point-in-time journal snapshot. Body: `{"target_sequence": 42}`

The exported `journal.jsonl` is **truncated at `target_sequence`** — the bundle
contains exactly the history it claims and no data written afterwards. The
snapshot directory also carries a `manifest.json` of per-file SHA-256 hashes;
the response's `integrity_sha256` is the SHA-256 of that manifest.

Snapshots are full copies of the base image and are capped (32 per namespace);
beyond that the endpoint returns 507 until old snapshots are removed.

### GET /v1/sizing
Storage sizing calculations for the current journal configuration.

## Token format

```
aegis1.<base64url(json-payload)>.<base64url(ed25519-signature)>
```

Payload fields: `action`, `device_id`, `state_version`, `target_sequence`,
`nonce`, `issued_unix`, `expires_unix`. Max TTL: 15 minutes. Each nonce is
single-use. `action` is `enter_recovery_read_only` or `enter_maintenance`.

## Unix control socket

Sensitive operations require local access and are not exposed over HTTP:

| Command | Effect |
|---|---|
| `status` | Engine status as JSON |
| `authorize <token>` | Enter `recovery_read_only` |
| `maintenance <token>` | Enter `maintenance` (re-enables writes) |
| `exit-maintenance` | Return to `normal` |
| `exit-maintenance compact` | Return to `normal` and compact the journal |
| `compact` | Compact the journal — refused outside `normal`/`maintenance` |

## Security headers

All responses carry `Content-Security-Policy`, `X-Content-Type-Options`,
`Referrer-Policy`, and `X-Frame-Options`. The API has no TLS; terminate it in a
reverse proxy.
