/**
 * Health & API Info Integration Tests
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { apiRequest, parseResponse, API_BASE_URL } from './setup';

describe('API Health & Info', () => {
    describe('GET /health', () => {
        it('should return healthy status', async () => {
            const response = await apiRequest('/health');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse(response);
            expect(data).toMatchObject({
                status: 'healthy',
                version: expect.any(String),
                timestamp: expect.any(String),
            });
        });
    });

    describe('GET /', () => {
        it('should return API info with all endpoints', async () => {
            const response = await apiRequest('/');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.name).toBe('RinjaniAnalytics API');
            expect(data.endpoints).toMatchObject({
                v1: '/v1',
                v2: '/v2',
                health: '/health',
            });
        });
    });
});

describe('API Versioning', () => {
    describe('V1 API (deprecated)', () => {
        it('should return deprecation header', async () => {
            const response = await apiRequest('/v1');

            expect(response.headers.get('deprecation')).toBe('true');
            expect(response.headers.get('x-api-version')).toBe('2.0');
            expect(response.headers.get('sunset')).toBeTruthy();
        });

        it('should include deprecation notice', async () => {
            const response = await apiRequest('/v1');

            const notice = response.headers.get('x-deprecation-notice');
            expect(notice).toContain('deprecated');
            expect(notice).toContain('v2');
        });
    });

    describe('V2 API (current)', () => {
        it('should return version headers without deprecation', async () => {
            const response = await apiRequest('/v2');

            expect(response.headers.get('x-api-version')).toBe('2.0');
            expect(response.headers.get('deprecation')).toBeNull();
        });

        it('should list available endpoints', async () => {
            const response = await apiRequest('/v2');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.endpoints).toMatchObject({
                bulk: '/v2/bulk',
                stix: '/v2/stix',
            });
        });
    });
});

describe('Rate Limiting', () => {
    it('should include rate limit headers', async () => {
        const response = await apiRequest('/v1/stats');

        expect(response.headers.get('x-ratelimit-limit')).toBeTruthy();
        expect(response.headers.get('x-ratelimit-remaining')).toBeTruthy();
    });
});
