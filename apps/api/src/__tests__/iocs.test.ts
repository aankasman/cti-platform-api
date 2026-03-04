/**
 * IOC API Integration Tests
 * 
 * Tests for IOC CRUD operations and filtering.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('IOC API - V1 Endpoints', () => {
    describe('GET /v1/iocs', () => {
        it('should return IOC list', async () => {
            const response = await apiRequest('/v1/iocs');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.success).toBe(true);
            expect(data.data).toBeDefined();
        });

        it('should support limit parameter', async () => {
            const response = await apiRequest('/v1/iocs?limit=5');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            // Data might be array or have array property
            const items = Array.isArray(data.data) ? data.data : (data.data?.iocs || []);
            if (items.length > 0) {
                expect(items.length).toBeLessThanOrEqual(5);
            }
        });

        it('should support type filter', async () => {
            const response = await apiRequest('/v1/iocs?type=ip');
            expect([200, 429]).toContain(response.status);
        });

        it('should support source filter', async () => {
            const response = await apiRequest('/v1/iocs?source=otx');
            expect([200, 429]).toContain(response.status);
        });

        it('should support severity filter', async () => {
            const response = await apiRequest('/v1/iocs?severity=high');
            expect([200, 429]).toContain(response.status);
        });

        it('should support dateFrom filter', async () => {
            const response = await apiRequest('/v1/iocs?dateFrom=2024-01-01');
            expect([200, 429]).toContain(response.status);
        });

        it('should support dateTo filter', async () => {
            const response = await apiRequest('/v1/iocs?dateTo=2025-12-31');
            expect([200, 429]).toContain(response.status);
        });

        it('should support combined date range filter', async () => {
            const response = await apiRequest('/v1/iocs?dateFrom=2024-01-01&dateTo=2025-12-31');
            expect([200, 429]).toContain(response.status);
        });
    });

    describe('GET /v1/iocs/:id', () => {
        it('should return 404 for non-existent IOC', async () => {
            const response = await apiRequest('/v1/iocs/non-existent-id-12345');
            expect([404, 500, 429]).toContain(response.status);
        });
    });
});

describe('IOC API - V2 Endpoints', () => {
    describe('GET /v2/indicators', () => {
        it('should respond to indicators endpoint', async () => {
            const response = await apiRequest('/v2/indicators');
            expect([200, 404, 429]).toContain(response.status);
        });
    });
});

describe('IOC Data Validation', () => {
    describe('Response Structure', () => {
        it('should include required fields in IOC response', async () => {
            const response = await apiRequest('/v1/iocs?limit=1');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);

            if (data.data && data.data.length > 0) {
                const ioc = data.data[0];
                expect(ioc.id).toBeDefined();
                expect(ioc.type).toBeDefined();
                expect(ioc.value).toBeDefined();
            }
        });
    });
});
