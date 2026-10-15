# Architecture

## Decision

The platform is an npm-workspace monorepo:

- `apps/web` — React, TypeScript, Vite, Tailwind, React Router, TanStack Query
- `apps/api` — NestJS REST API, OpenAPI, WebSocket progress
- `apps/worker` — BullMQ consumers for scans, graph rebuilds, and maintenance
- `packages/shared` — Zod contracts, RBAC, policy predicates
- `packages/security` — Argon2id, secret masking, SSRF checks, path allowlists
- `packages/risk-engine` — contextual risk formula
- `packages/attack-path-engine` — graph traversal
- `packages/scanner-adapters` — Semgrep, Trivy, OWASP ZAP, Gitleaks
- `packages/integrations` — email provider abstraction
- `packages/db` — Prisma schema and client

PostgreSQL is the system of record. Redis backs BullMQ and scan-progress pub/sub. Scans never run inside the HTTP request.

## Request path

Browser → API (cookie or bearer) → organization guard → Prisma.

Scan request → `scans` queue → worker → scanner adapter → parser → normalization → deduplicated vulnerability → risk score → attack-path rebuild → notification.

## Tenancy

Every security record stores `organizationId`. Services resolve the organization from the authenticated membership. A platform admin must send `X-Organization-Id`. Cross-tenant identifiers return 404. Authorization is enforced in Nest guards, not in the UI.

## Roles

Permissions live in code (`ROLE_PERMISSIONS`) so a database edit cannot invent a new privilege. Membership stores the role. `RESOLVED` is not a client-writable finding status; only a completed validation scan sets it.

## MVP boundary

Included: authentication, MFA enrollment, RBAC, assets, four scanner adapters, normalization, dedup, risk, attack paths, incidents, remediation, validation, events, notifications, reports, audit, dashboard, Docker, CI, Kubernetes manifests, and a Terraform baseline.

Not implemented, and not presented as live integrations: Nessus, Qualys, CrowdStrike, Microsoft Defender, AWS Security Hub, GuardDuty, Wazuh, Splunk, Microsoft Sentinel. The adapter boundary is the extension point.

## Security-sensitive components

Authentication and refresh-token storage, MFA secret encryption, tenant scoping, scan target SSRF controls, secret masking before persistence, audit immutability, file upload allowlists, and the local security lab.
