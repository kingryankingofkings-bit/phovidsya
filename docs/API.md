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
Issue a one-time challenge nonce. Body: `{"action": "enter_recovery_read_only"}`

### POST /v1/authorize
Submit signed recovery token. Body: `{"challenge_id": "...", "token": "aegis1...", "physical_presence": true}`

### POST /v1/recovery/export
Create a point-in-time journal snapshot. Body: `{"target_sequence": 42}`

### GET /v1/sizing
Storage sizing calculations for the current journal configuration.

## Token format

```
aegis1.<base64url(json-payload)>.<base64url(ed25519-signature)>
```

Payload fields: `action`, `device_id`, `state_version`, `target_sequence`, `nonce`, `issued_unix`, `expires_unix`. Max TTL: 15 minutes. Each nonce is single-use.
