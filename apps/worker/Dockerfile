# =============================================================================
# V3 Worker Dockerfile
# =============================================================================
# Single-stage build with tsx runtime.
# The monorepo uses noEmit:true so tsc only type-checks, tsx runs TS at runtime.
# Uses Debian-slim (not Alpine) for glibc compatibility.

FROM node:20-slim

# Install pnpm
RUN corepack enable && corepack prepare pnpm@8 --activate

# Security: non-root user (created early, used later)
RUN groupadd -g 1001 nodejs && \
    useradd -u 1001 -g nodejs -s /bin/sh -m nodejs

WORKDIR /app

# Copy package files first for better layer caching
COPY --chown=nodejs:nodejs pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY --chown=nodejs:nodejs apps/worker/package.json ./apps/worker/
COPY --chown=nodejs:nodejs apps/api/package.json ./apps/api/
COPY --chown=nodejs:nodejs packages/db/package.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/package.json ./packages/core/

# Install all dependencies (tsx is needed at runtime)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY --chown=nodejs:nodejs tsconfig.base.json ./
COPY --chown=nodejs:nodejs apps/worker/tsconfig.json ./apps/worker/
COPY --chown=nodejs:nodejs apps/worker/src ./apps/worker/src
COPY --chown=nodejs:nodejs apps/api/tsconfig.json ./apps/api/
COPY --chown=nodejs:nodejs apps/api/src ./apps/api/src
COPY --chown=nodejs:nodejs packages/db/src ./packages/db/src
COPY --chown=nodejs:nodejs packages/db/tsconfig.json ./packages/db/
COPY --chown=nodejs:nodejs packages/core/src ./packages/core/src
COPY --chown=nodejs:nodejs packages/core/tsconfig.json ./packages/core/

# Create plugins directory
RUN mkdir -p /app/plugins && chown nodejs:nodejs /app/plugins

# Environment
ENV NODE_ENV=production
ENV PLUGINS_DIR=/app/plugins

# Switch to non-root user
USER nodejs

# Start the worker using node with tsx loader (tsx is in API workspace's node_modules)
ENV NODE_PATH=/app/apps/api/node_modules
CMD ["node", "--import", "tsx/esm", "apps/worker/src/index.ts", "--daemon"]
