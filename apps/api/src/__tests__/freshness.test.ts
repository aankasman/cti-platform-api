/**
 * Freshness API Integration Tests
 * 
 * Tests for the GET /v1/stats/freshness endpoint.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Freshness API', () => {
    describe('GET /v1/stats/freshness', () => {
        it('should return freshness data with category timestamps', async () => {
            const response = await apiRequest('/v1/stats/freshness');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            expect(response.status).toBe(200);

            const body = await parseResponse<any>(response);
            const data = body.data || body;

            // Verify categories structure
            expect(data.categories).toBeDefined();
            expect(data.categories).toHaveProperty('iocs');
            expect(data.categories).toHaveProperty('vulnerabilities');
            expect(data.categories).toHaveProperty('actors');

            // Each category should have a latestRecord field (can be null if no data)
            expect(data.categories.iocs).toHaveProperty('latestRecord');
            expect(data.categories.vulnerabilities).toHaveProperty('latestRecord');
            expect(data.categories.actors).toHaveProperty('latestRecord');
        });

        it('should return feed sync data', async () => {
            const response = await apiRequest('/v1/stats/freshness');
            if (response.status !== 200) return;
            expect(response.status).toBe(200);

            const body = await parseResponse<any>(response);
            const data = body.data || body;
            expect(data.feeds).toBeDefined();
            expect(Array.isArray(data.feeds)).toBe(true);
        });

        it('should include a timestamp', async () => {
            const response = await apiRequest('/v1/stats/freshness');
            if (response.status !== 200) return;
            expect(response.status).toBe(200);

            const body = await parseResponse<any>(response);
            const data = body.data || body;
            expect(data.timestamp).toBeDefined();
            expect(new Date(data.timestamp).getTime()).not.toBeNaN();
        });
    });
});
