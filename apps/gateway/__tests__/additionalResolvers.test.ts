import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import additionalResolvers from '../src/additionalResolvers';

// ============================================================================
// Helpers
// ============================================================================

function mockFetchResponse(data: unknown, status = 200) {
    return vi.fn().mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        statusText: status === 200 ? 'OK' : 'Error',
        json: () => Promise.resolve(data),
    });
}

// ============================================================================
// Additional Resolvers Tests
// ============================================================================

describe('Gateway Additional Resolvers', () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
        vi.restoreAllMocks();
    });

    // --- Query.auditLogs ---

    describe('Query.auditLogs', () => {
        const resolver = additionalResolvers.Query.auditLogs;

        // Resolver returns the REST payload pass-through: `{ entries, total }`
        // shape from `/admin/audit`. (Predecessor: `/v1/audit` returning a
        // bare array — the tests below were authored against that older
        // shape and are now updated to track the current resolver.)

        it('fetches audit logs from REST API', async () => {
            const mockEntries = [
                { id: '1', action: 'create', entityType: 'ioc', userId: 'user1', createdAt: '2026-01-01' },
                { id: '2', action: 'update', entityType: 'vuln', userId: 'user2', createdAt: '2026-01-02' },
            ];
            globalThis.fetch = mockFetchResponse({ entries: mockEntries, total: 2 });

            const result = await resolver(null, { limit: 10 });

            expect(result.entries).toHaveLength(2);
            expect(result.entries[0]).toEqual(expect.objectContaining({ id: '1', action: 'create' }));
            expect(result.entries[1]).toEqual(expect.objectContaining({ id: '2', action: 'update' }));
            expect(result.total).toBe(2);
        });

        it('passes limit parameter to REST API', async () => {
            globalThis.fetch = mockFetchResponse({ entries: [], total: 0 });

            await resolver(null, { limit: 5 });

            const url = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
            expect(url).toContain('/admin/audit?limit=5');
        });

        it('omits limit param when not provided', async () => {
            // Resolver doesn't synthesize a default — if no limit is passed,
            // the upstream is called without one and applies its own
            // server-side default. The old behaviour with a client-side
            // default of 20 isn't part of the current contract.
            globalThis.fetch = mockFetchResponse({ entries: [], total: 0 });

            await resolver(null, {});

            const url = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
            expect(url).not.toContain('limit=');
        });

        it('returns empty entries on REST error', async () => {
            globalThis.fetch = mockFetchResponse({}, 500);

            const result = await resolver(null, { limit: 10 });

            // safeFetch fallback on non-2xx → the resolver's hard-coded
            // empty page shape `{ entries: [], total: 0 }`.
            expect(result).toEqual({ entries: [], total: 0 });
        });

        it('returns empty entries on network failure', async () => {
            globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

            const result = await resolver(null, {});

            expect(result).toEqual({ entries: [], total: 0 });
        });

        it('passes through REST response as-is when 2xx (even if shape is incomplete)', async () => {
            // safeFetch is a thin wrapper — it doesn't normalize successful
            // responses. If REST returns `{}` with a 200, the resolver
            // returns `{}`. GraphQL clients tolerate the missing optional
            // `entries`/`total` fields via the schema's `JSON` typing.
            globalThis.fetch = mockFetchResponse({});

            const result = await resolver(null, {});

            expect(result).toEqual({});
        });
    });

    // --- Query.systemHealth ---

    describe('Query.systemHealth', () => {
        const resolver = additionalResolvers.Query.systemHealth;

        it('fetches health status from REST API', async () => {
            const mockHealth = {
                status: 'ok',
                uptime: 12345,
                timestamp: '2026-01-01T00:00:00Z',
                services: { db: 'ok', redis: 'ok' },
            };
            globalThis.fetch = mockFetchResponse(mockHealth);

            const result = await resolver(null, {});

            expect(result).toEqual(expect.objectContaining({
                status: 'ok',
                uptime: 12345,
            }));
        });

        it('calls /health endpoint', async () => {
            globalThis.fetch = mockFetchResponse({ status: 'ok' });

            await resolver(null, {});

            const url = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
            expect(url).toContain('/health');
        });

        it('returns unreachable on REST error', async () => {
            globalThis.fetch = mockFetchResponse({}, 500);

            const result = await resolver(null, {});

            expect(result).toEqual(expect.objectContaining({ status: 'unreachable' }));
        });

        it('returns unreachable on network failure', async () => {
            globalThis.fetch = vi.fn().mockRejectedValue(new Error('connection refused'));

            const result = await resolver(null, {});

            expect(result.status).toBe('unreachable');
        });

        it('returns default timestamp when health response lacks one', async () => {
            globalThis.fetch = mockFetchResponse({ status: 'ok', uptime: 100 });

            const result = await resolver(null, {});

            expect(result.timestamp).toBeDefined();
            expect(typeof result.timestamp).toBe('string');
        });
    });

    // --- JSON scalar ---

    describe('JSON scalar', () => {
        it('serializes values as-is', () => {
            const value = { nested: { data: [1, 2, 3] } };
            expect(additionalResolvers.JSON.__serialize(value)).toBe(value);
        });

        it('parses values as-is', () => {
            const value = 'some string';
            expect(additionalResolvers.JSON.__parseValue(value)).toBe(value);
        });

        it('parseLiteral returns null', () => {
            expect(additionalResolvers.JSON.__parseLiteral()).toBeNull();
        });
    });
});
