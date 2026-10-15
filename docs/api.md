# API

Interactive documentation is served at `/api/docs`.

Authentication:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `GET /api/auth/csrf`
- `POST /api/auth/mfa/enroll`
- `POST /api/auth/mfa/verify`
- `POST /api/auth/switch-organization`

Operational resources use bearer auth or the access cookie. Browser cookie calls send `x-csrf-token`. Platform admins send `X-Organization-Id`.

Main collections: `/api/assets`, `/api/findings`, `/api/vulnerabilities/:id`, `/api/scans`, `/api/attack-paths`, `/api/incidents`, `/api/remediations`, `/api/events`, `/api/notifications`, `/api/reports/export`, `/api/dashboard`, `/api/audit`, `/api/policies`, `/api/users`.

Probes: `/health`, `/ready`, `/metrics`.

Errors use `{ error: { code, message, details, requestId } }`. List endpoints use `{ data, page, pageSize, total }`.
