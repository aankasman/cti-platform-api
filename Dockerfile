# =============================================================================
# V3 Unified Dockerfile — API + Worker
# =============================================================================
# Single image for both API server and background workers.
# Uses tsx runtime (noEmit:true monorepo — no tsc build step needed).
# Debian-slim (not Alpine) because onnxruntime requires glibc.
#
# Usage in docker-compose.yml:
#   v3-api:    (default CMD runs API)
#   v3-worker: command: ["node", "--import", "tsx/esm", "apps/worker/src/index.ts", "--daemon"]

FROM node:20-slim

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8 --activate

# Security: non-root user
RUN groupadd -g 1001 nodejs && \
    useradd -u 1001 -g nodejs -s /bin/sh -m nodejs

# Install wget for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Package manifests (layer cache) ──
COPY --chown=nodejs:nodejs pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY --chown=nodejs:nodejs apps/api/package.json ./apps/api/
COPY --chown=nodejs:nodejs apps/worker/package.json ./apps/worker/
COPY --chown=nodejs:nodejs packages/db/package.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/package.json ./packages/core/

# Install all dependencies (tsx needed at runtime)
RUN pnpm install --frozen-lockfile

# ── Source code (api + worker + shared packages) ──
COPY --chown=nodejs:nodejs tsconfig.base.json ./
COPY --chown=nodejs:nodejs apps/api/tsconfig.json ./apps/api/
COPY --chown=nodejs:nodejs apps/api/src ./apps/api/src
COPY --chown=nodejs:nodejs apps/worker/tsconfig.json ./apps/worker/
COPY --chown=nodejs:nodejs apps/worker/src ./apps/worker/src
COPY --chown=nodejs:nodejs packages/db/src ./packages/db/src
COPY --chown=nodejs:nodejs packages/db/tsconfig.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/src ./packages/core/src
COPY --chown=nodejs:nodejs packages/core/tsconfig.json ./packages/core/

# Create plugins directory for worker
RUN mkdir -p /app/plugins && chown nodejs:nodejs /app/plugins

# Environment
ENV NODE_ENV=production
ENV PORT=3001
ENV PLUGINS_DIR=/app/plugins
ENV NODE_PATH=/app/apps/api/node_modules

# Switch to non-root user
USER nodejs

# Expose API port (only used when running as API)
EXPOSE 3001

# Note: HEALTHCHECK is NOT defined here because this image serves both
# API (has /health endpoint) and Worker (no HTTP server). Each service
# defines its own healthcheck in docker-compose.yml.

# Default: run API server
CMD ["./apps/api/node_modules/.bin/tsx", "apps/api/src/index.ts"]
