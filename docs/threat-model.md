# Threat model

## Trust boundaries

```text
Analyst browser
    |  HTTPS, cookie or bearer
API + worker
    |  SQL / Redis
PostgreSQL, Redis, scan workspace
    |
Scanner processes and optional ZAP API
    |
Allowlisted repositories, images, and lab URLs
```

The development security lab is outside the production trust boundary and is bound to localhost.

## Assets

Tenant vulnerability data, user credentials, refresh-token hashes, MFA secrets, scan evidence, audit history, and cloud deployment credentials.

## STRIDE

| Threat | Example | Mitigation |
| --- | --- | --- |
| Spoofing | Stolen access token | Short TTL, rotation, lockout, optional TOTP |
| Tampering | Cross-tenant object id | Server-side organization filter, 404 on miss |
| Repudiation | Silent status change | Append-only audit log |
| Information disclosure | Secret printed in a finding | Masking before persistence and reports |
| Denial of service | Scan request flood | Queue, throttling, command timeout, body limits |
| Elevation | Viewer starts a scan or marks a finding resolved | RBAC and validation-only resolution |

## Abuse cases

- An authenticated user guesses another tenant's asset id. The query includes both id and organization id.
- A scan URL targets the cloud metadata address. The SSRF check rejects it before queueing.
- A scanner reports a live credential. The value is replaced with `[REDACTED]`.
- A user marks a finding resolved in the browser. The API schema rejects `RESOLVED`.

## Data flow

Discover assets → queue scan → worker runs an adapter → parser emits normalized findings → database deduplicates → risk engine scores → attack-path engine walks stored edges → analyst triages → validation scan confirms the fix.
