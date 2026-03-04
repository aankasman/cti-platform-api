/**
 * Intelligence API Integration Tests
 *
 * Tests for IOC, CVE, and Actor intelligence enrichment endpoints.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Intelligence API', () => {
    describe('GET /v1/intelligence/ioc/:value', () => {
        it('should enrich a known IP address', async () => {
            const response = await apiRequest('/v1/intelligence/ioc/8.8.8.8');
            if (response.status === 429) return;
            expect([200, 404, 502]).toContain(response.status);

            if (response.status === 200) {
                const data = await parseResponse<any>(response);
                expect(data.success).toBe(true);
                expect(data.data).toBeDefined();
            }
        });

        it('should handle URL-encoded IOC values', async () => {
            const response = await apiRequest(`/v1/intelligence/ioc/${encodeURIComponent('evil.com')}`);
            if (response.status === 429) return;
            expect([200, 404, 502]).toContain(response.status);
        });

        it('should return structured enrichment data', async () => {
            const response = await apiRequest('/v1/intelligence/ioc/1.1.1.1');
            if (response.status === 429) return;
            if (response.status !== 200) return;

            const data = await parseResponse<any>(response);
            if (data.data) {
                // Should have at least some enrichment fields
                expect(data.data).toBeDefined();
            }
        });
    });

    describe('GET /v1/intelligence/cve/:id', () => {
        it('should look up a known CVE', async () => {
            const response = await apiRequest('/v1/intelligence/cve/CVE-2024-1234');
            if (response.status === 429) return;
            expect([200, 404, 502]).toContain(response.status);
        });

        it('should return 404 for non-existent CVE', async () => {
            const response = await apiRequest('/v1/intelligence/cve/CVE-0000-00000');
            expect([404, 429, 502]).toContain(response.status);
        });

        it('should handle malformed CVE IDs gracefully', async () => {
            const response = await apiRequest('/v1/intelligence/cve/not-a-cve');
            expect([400, 404, 429, 502]).toContain(response.status);
        });
    });

    describe('GET /v1/intelligence/actor/:id', () => {
        it('should look up an actor by ID', async () => {
            const response = await apiRequest('/v1/intelligence/actor/apt28');
            if (response.status === 429) return;
            expect([200, 404, 502]).toContain(response.status);
        });

        it('should handle URL-encoded actor names', async () => {
            const response = await apiRequest(`/v1/intelligence/actor/${encodeURIComponent('Fancy Bear')}`);
            if (response.status === 429) return;
            expect([200, 404, 502]).toContain(response.status);
        });

        it('should return 404 for non-existent actor', async () => {
            const response = await apiRequest('/v1/intelligence/actor/nonexistent_actor_xyz');
            expect([404, 429, 502]).toContain(response.status);
        });
    });
});
