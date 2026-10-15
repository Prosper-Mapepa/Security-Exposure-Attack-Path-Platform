FROM node:20-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git python3 python3-pip openssl && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
  pip3 install --break-system-packages semgrep; \
  curl -fsSL -o /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz; \
  tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
  curl -fsSL -o /tmp/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_linux_x64.tar.gz; \
  tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
  rm -f /tmp/trivy.tar.gz /tmp/gitleaks.tar.gz
COPY package.json package-lock.json* ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
COPY packages packages
RUN npm install
COPY . .
RUN npm run build -w @seap/shared && npm run build -w @seap/security && npm run build -w @seap/risk-engine && npm run build -w @seap/attack-path-engine && npm run build -w @seap/scanner-adapters && npm run build -w @seap/integrations && npm run prisma:generate -w @seap/db && npm run build -w @seap/db && npm run build -w @seap/worker
CMD ["node", "apps/worker/dist/main.js"]
