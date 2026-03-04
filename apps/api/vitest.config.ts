import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['src/__tests__/**/*.test.ts'],
        setupFiles: ['src/__tests__/setup.ts'],
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
