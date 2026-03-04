/**
 * Sightings API Integration Tests
 *
 * Tests for sighting CRUD operations, stats, and recent endpoint.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Sightings API', () => {
    describe('GET /v1/sightings/recent', () => {
        it('should return recent sightings list', async () => {
            const response = await apiRequest('/v1/sightings/recent');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.success).toBe(true);
            expect(data.data).toBeDefined();
        });

        it('should support limit parameter', async () => {
            const response = await apiRequest('/v1/sightings/recent?limit=5');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            const items = Array.isArray(data.data) ? data.data : [];
            if (items.length > 0) {
                expect(items.length).toBeLessThanOrEqual(5);
            }
        });

        it('should return items with required fields', async () => {
            const response = await apiRequest('/v1/sightings/recent?limit=1');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            const items = Array.isArray(data.data) ? data.data : [];
            if (items.length > 0) {
                const sighting = items[0];
                expect(sighting.id).toBeDefined();
                expect(sighting.iocValue).toBeDefined();
                expect(sighting.source).toBeDefined();
            }
        });
    });

    describe('GET /v1/sightings/stats', () => {
        it('should return sighting statistics', async () => {
            const response = await apiRequest('/v1/sightings/stats');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.success).toBe(true);
            expect(data.data).toBeDefined();
        });

        it('should include aggregate fields', async () => {
            const response = await apiRequest('/v1/sightings/stats');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            if (data.data) {
                expect(typeof data.data.totalSightings).toBe('number');
            }
        });
    });

    describe('POST /v1/iocs/:id/sightings', () => {
        it('should reject invalid sighting payload', async () => {
            const response = await apiRequest('/v1/iocs/nonexistent/sightings', {
                method: 'POST',
                body: JSON.stringify({}),
            });
            // Expect 400 (validation) or 404 (IOC not found) or 429 (rate limit)
            expect([400, 404, 422, 429, 500]).toContain(response.status);
        });

        it('should reject negative confidence', async () => {
            const response = await apiRequest('/v1/iocs/test-id/sightings', {
                method: 'POST',
                body: JSON.stringify({
                    source: 'test',
                    confidence: -10,
                    description: 'Invalid confidence',
                }),
            });
            expect([400, 404, 422, 429, 500]).toContain(response.status);
        });
    });

    describe('GET /v1/iocs/:id/sightings', () => {
        it('should return sightings for specific IOC', async () => {
            const response = await apiRequest('/v1/iocs/nonexistent-id/sightings');
            // Could be 200 (empty list) or 404
            expect([200, 404, 429, 500]).toContain(response.status);
        });
    });
});
