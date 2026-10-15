FROM node:20-bookworm-slim
WORKDIR /lab
COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install --omit=dev --package-lock-only && npm install --omit=dev
COPY src ./src
EXPOSE 8090
USER node
CMD ["node", "src/server.js"]
