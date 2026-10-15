# Security Exposure & Attack Path Platform

Security teams use this platform to inventory assets, run Semgrep, Trivy, Gitleaks, and OWASP ZAP, normalize the results, score them with business context, trace attack paths, and prove a fix with a second scan.

The dashboard reads PostgreSQL. An empty organization says “No security data available”.

## Architecture

`apps/web` is the analyst console. `apps/api` is the NestJS API. `apps/worker` consumes BullMQ jobs and runs scanners outside the request cycle. Shared packages hold the risk formula, attack-path traversal, scanner adapters, and security helpers. PostgreSQL stores tenant data. Redis stores queue state and scan progress.

See [docs/architecture.md](docs/architecture.md).

## Features

- Email and password authentication with Argon2id, rotating refresh tokens, CSRF for cookie sessions, lockout, and TOTP enrollment
- Organization tenancy and RBAC for platform admin, security admin, analyst, engineer, and viewer
- Asset inventory for applications, APIs, repositories, cloud resources, containers, and Kubernetes objects
- Scanner adapters, queued execution, normalization, and deduplication
- Contextual risk scores with the factors shown to the analyst
- Attack-path discovery from stored relationships
- Incidents, remediation, comments, evidence, and validation scans
- Events, in-app notifications, an email adapter, PDF/CSV/JSON reports, and append-only audit logs

## Tech stack

React, TypeScript, Vite, Tailwind, NestJS, Prisma, PostgreSQL, Redis, BullMQ, Docker, GitHub Actions, Kubernetes manifests, and Terraform for AWS.

## Local setup

```bash
cp .env.example .env
docker compose up postgres redis -d
npm install
npm run db:generate
npm run db:deploy
npm run db:seed
npm run dev:api
npm run dev:worker
npm run dev:web
```

Open `http://localhost:5173`, create an organization, add an asset, and queue a scan whose path is inside `SCAN_PATH_ALLOWLIST`.

## Environment variables

Copy `.env.example`. Required secrets are `JWT_ACCESS_SECRET`, `MFA_ENCRYPTION_KEY`, `DATABASE_URL`, and `REDIS_URL`. Do not commit `.env`.

## Database

Prisma schema: `packages/db/prisma/schema.prisma`.

```bash
npm run db:migrate
npm run db:deploy
npm run db:seed
```

`db:deploy` applies committed migrations. Seed creates a platform admin only when `SEED_ADMIN_EMAIL` and `SEED_ADMIN_PASSWORD` are set. It does not insert findings.

## Scanners

Install Semgrep, Trivy, and Gitleaks on the worker host, or use the worker image. Point ZAP at `ZAP_BASE_URL`. Details are in [docs/scanners.md](docs/scanners.md).

The development security lab is optional:

```bash
docker compose --profile lab up lab
```

It listens on `127.0.0.1:8090` and is labeled DEVELOPMENT SECURITY LAB. Scan `lab/src` with Semgrep, Trivy, or Gitleaks. After `node lab/scripts/apply-fix.js`, a validation scan can resolve the source finding.

## Tests

```bash
npm run test:unit
npm run test:e2e
npm run lint
npm run typecheck
```

## Docker

```bash
docker compose up --build
```

Web is published on `127.0.0.1:8080`. API is on `127.0.0.1:4000`.

## AWS

Review [docs/deployment.md](docs/deployment.md) and `infrastructure/terraform`. Plan only. Do not apply without explicit configuration.

## Security model

Tenant isolation is enforced in the API. Finding resolution requires a validation scan. Secrets are masked before they are stored or reported. The threat model is in [docs/threat-model.md](docs/threat-model.md).

## Further reading

- [Risk formula](docs/risk-engine.md)
- [Attack paths](docs/attack-paths.md)
- [API](docs/api.md)
- [Roadmap](docs/roadmap.md)
