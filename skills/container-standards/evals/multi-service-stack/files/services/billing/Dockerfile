# syntax=docker/dockerfile:1
FROM node:24.11.0-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

FROM node:24.11.0-bookworm-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24.11.0-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/node_modules ./node_modules
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/server.js"]
