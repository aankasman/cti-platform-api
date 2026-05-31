import { defineConfig } from 'vitest/config';

/**
 * Integration test suite — runs against a real, running stack.
 *
 * Expects the dev environment to be up: `docker compose up -d` for
 * Postgres + Redis + Neo4j + OpenSearch, then `pnpm dev` from the
 * repo root to start the API on :3001. Then run:
 *
 *   pnpm --filter @rinjani/api test:integration
 *
 * Tests under `src/__tests__/integration/` use `apiRequest()` from
 * `setup.ts` to fetch `http://localhost:3001/...` — so the API really
 * does need to be listening.
 */
export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['src/__tests__/integration/**/*.test.ts'],
        setupFiles: ['src/__tests__/integration/setup.ts'],
        testTimeout: 30000,
        hookTimeout: 30000,
    },
    resolve: {
        alias: {
            '@': '/src',
        },
    },
});
