# Security model

## Authentication

Passwords are hashed with Argon2id. Access tokens are JWTs (15 minutes) delivered in an HTTP-only cookie and in the JSON body for API clients. Refresh tokens are random, stored only as SHA-256 hashes, rotated on use, and the token family is revoked if a used token is presented again. Browser mutations that rely on cookies require a double-submit CSRF token. Bearer requests are exempt because a browser cannot attach that header cross-site.

Five failed logins lock the account for 15 minutes. Auth routes are rate limited by the global throttler. Reset tokens expire in one hour and are single use. In production the reset token is only emailed. `EXPOSE_RESET_TOKEN` is ignored when `NODE_ENV=production`.

TOTP secrets are encrypted with AES-256-GCM before storage. Enrollment does not enable MFA until a code verifies.

## Authorization

`JwtAuthGuard` reloads membership on every request. `PermissionsGuard` checks the code-defined matrix. Tenant id comes from the token, not the body.

## Data protection

Logs and stored evidence pass through secret masking. Gitleaks match text is stripped before the adapter returns a payload, and the report file is deleted. Dashboard and PDF/CSV output use the masked fields. CSV cells that start with formula characters are prefixed.

## Scan safety

Path targets must sit inside `SCAN_PATH_ALLOWLIST`. URL and git targets must be `http` or `https`, must not embed credentials, and must not resolve to loopback, link-local, or private ranges unless `ALLOW_PRIVATE_SCAN_TARGETS=true` and the address is inside `LAB_NETWORK_CIDR`. Image references reject traversal and whitespace.

## Uploads

Remediation evidence accepts PNG, JPEG, PDF, text, JSON, and CSV, with a 5 MB default limit.

## Audit

`AuditLog` has no update method in the service. The migration installs a trigger that rejects `UPDATE` and `DELETE`.

## Application controls

Helmet, CORS allowlist, 1 MB JSON limit, Prisma parameterized queries, request ids, and structured logs that omit authorization headers, cookies, passwords, and tokens.
