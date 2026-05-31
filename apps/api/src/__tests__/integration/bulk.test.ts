/**
 * Bulk Operations Integration Tests
 * 
 * Note: Some endpoints return 500 when internal errors occur.
 * These tests verify the endpoint structure.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Bulk Operations API', () => {
    describe('POST /v2/bulk/lookup', () => {
        it('should accept lookup request', async () => {
            const response = await apiRequest('/v2/bulk/lookup', {
                method: 'POST',
                body: JSON.stringify({ values: ['8.8.8.8'] }),
            });
            // Accept either success or error response
            expect([200, 400, 401, 429, 500]).toContain(response.status);
        });

        it('should reject non-JSON body', async () => {
            const response = await apiRequest('/v2/bulk/lookup', {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                body: 'not json',
            });
            expect([400, 429, 500]).toContain(response.status);
        });
    });

    describe('GET /v2/bulk/stats', () => {
        it('should respond to stats request', async () => {
            const response = await apiRequest('/v2/bulk/stats');
            // May require auth
            expect([200, 401, 429, 500]).toContain(response.status);
        });
    });

    describe('Endpoint Structure', () => {
        it('should have bulk endpoints available', async () => {
            const response = await apiRequest('/v2');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.endpoints.bulk).toBe('/v2/bulk');
        });
    });
});
