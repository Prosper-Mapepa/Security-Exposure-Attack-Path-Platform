# Development

## Local services

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

The web app is at `http://localhost:5173`. The API is at `http://localhost:4000` and OpenAPI at `http://localhost:4000/api/docs`.

## Full stack

```bash
docker compose up --build
```

Add the lab only when you intend to scan it:

```bash
docker compose --profile lab up --build
```

ZAP stays off unless you start its profile. It listens only on `127.0.0.1:8091`. The default API key `local-dev-zap-key` is for this local daemon; set `ZAP_API_KEY` before use anywhere else.

```bash
docker compose --profile zap --profile lab up zap lab
```

Point the worker at `ZAP_BASE_URL=http://127.0.0.1:8091` and the same `ZAP_API_KEY`. Inside Compose, the worker uses `http://zap:8080` and can scan the lab at `http://lab:8090`.

## Tests

```bash
npm run test:unit
npm run test:e2e
```

E2E tests need PostgreSQL and Redis from Compose and an applied migration.

## Quality checks

```bash
npm run lint
npm run typecheck
```
