import { defineConfig } from 'vitest/config';

/**
 * Default test suite — UNIT tests only.
 *
 * Files under `src/__tests__/integration/` are intentionally excluded:
 * they `fetch('http://localhost:3001/...')` and require the full local
 * stack (Postgres + Redis + Neo4j + OpenSearch + the API itself
 * running). CI doesn't have Neo4j or OpenSearch as service containers,
 * so the integration suite is opt-in via `pnpm test:integration`
 * (uses vitest.integration.config.ts) against a local dev stack.
 *
 * Adding a new test that needs upstream services? Drop it under
 * `src/__tests__/integration/` and the default `pnpm test` will skip
 * it; `pnpm test:integration` will pick it up.
 *
 * setupFiles is intentionally NOT set here — the only setup file
 * (`integration/setup.ts`) flushes Redis rate-limit keys, which the
 * unit suite doesn't need.
 */
export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['src/__tests__/**/*.test.ts'],
        exclude: ['**/node_modules/**', 'src/__tests__/integration/**'],
        testTimeout: 30000,
        hookTimeout: 30000,
        coverage: {
            reporter: ['text', 'html'],
            include: ['src/**/*.ts'],
            exclude: ['src/__tests__/**', 'src/index.ts'],
        },
    },
    resolve: {
        alias: {
            '@': '/src',
        },
    },
});
