FROM node:20-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY packages/db/package.json packages/db/
COPY packages/security/package.json packages/security/
COPY packages/risk-engine/package.json packages/risk-engine/
COPY packages/attack-path-engine/package.json packages/attack-path-engine/
COPY packages/scanner-adapters/package.json packages/scanner-adapters/
COPY packages/integrations/package.json packages/integrations/
RUN npm install
COPY . .
RUN npm run build -w @seap/shared && npm run build -w @seap/security && npm run build -w @seap/risk-engine && npm run build -w @seap/attack-path-engine && npm run build -w @seap/scanner-adapters && npm run build -w @seap/integrations && npm run prisma:generate -w @seap/db && npm run build -w @seap/db && npm run build -w @seap/api
EXPOSE 4000
CMD ["sh", "-c", "npm run prisma:deploy -w @seap/db && npm run seed -w @seap/db && node apps/api/dist/main.js"]
