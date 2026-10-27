FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
RUN npm install
COPY . .
RUN npm run build -w @seap/shared && npm run build -w @seap/web

FROM nginx:1.27-alpine
ENV PORT=80
# Overridden in docker-compose. On Railway set API_UPSTREAM=http://api.railway.internal:<api PORT>.
ENV API_UPSTREAM=http://api.railway.internal:8080
ENV API_PORT=8080
COPY infrastructure/docker/default.conf.template /etc/nginx/templates/default.conf.template
COPY infrastructure/docker/web-entrypoint.sh /web-entrypoint.sh
RUN chmod +x /web-entrypoint.sh
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
ENTRYPOINT ["/web-entrypoint.sh"]
