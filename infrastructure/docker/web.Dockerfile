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
ENV API_UPSTREAM=http://api:4000
COPY infrastructure/docker/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
EXPOSE 80
