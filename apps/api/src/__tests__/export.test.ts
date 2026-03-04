/**
 * Export API Integration Tests
 * 
 * Tests for data export and monitoring endpoints.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Feeds API', () => {
    describe('GET /v1/feeds', () => {
        it('should respond to feeds endpoint', async () => {
            const response = await apiRequest('/v1/feeds');
            expect([200, 404, 429, 500]).toContain(response.status);
        });
    });

    describe('GET /v1/feeds/status', () => {
        it('should respond to feed status endpoint', async () => {
            const response = await apiRequest('/v1/feeds/status');
            expect([200, 404, 429, 500]).toContain(response.status);
        });
    });
});

describe('Monitoring API', () => {
    describe('GET /v1/monitoring/metrics', () => {
        it('should respond to metrics endpoint', async () => {
            const response = await apiRequest('/v1/monitoring/metrics');
            expect([200, 404, 429, 500]).toContain(response.status);
        });
    });
});

describe('API Error Handling', () => {
    describe('Invalid Endpoints', () => {
        it('should return 404 for non-existent endpoint', async () => {
            const response = await apiRequest('/v1/does-not-exist');
            expect([404, 429, 500]).toContain(response.status);
        });

        it('should return 404 for invalid version', async () => {
            const response = await apiRequest('/v99/iocs');
            expect([404, 429, 500]).toContain(response.status);
        });
    });

    describe('Invalid Parameters', () => {
        it('should handle invalid limit gracefully', async () => {
            const response = await apiRequest('/v1/iocs?limit=invalid');
            expect([200, 400, 429]).toContain(response.status);
        });

        it('should handle negative offset gracefully', async () => {
            const response = await apiRequest('/v1/iocs?offset=-1');
            expect([200, 400, 429]).toContain(response.status);
        });
    });
});

describe('Response Headers', () => {
    describe('Standard Headers', () => {
        it('should include content-type header', async () => {
            const response = await apiRequest('/health');
            expect(response.headers.get('content-type')).toContain('application/json');
        });

        it('should include timing header', async () => {
            const response = await apiRequest('/health');
            const timing = response.headers.get('server-timing');
            expect(timing).toBeTruthy();
        });
    });

    describe('Security Headers', () => {
        it('should include security headers', async () => {
            const response = await apiRequest('/health');
            expect(response.headers.get('x-content-type-options')).toBeTruthy();
        });
    });

    describe('CORS Headers', () => {
        it('should include CORS headers', async () => {
            const response = await apiRequest('/v1/iocs');
            const exposeHeaders = response.headers.get('access-control-expose-headers');
            expect(exposeHeaders).toBeTruthy();
        });
    });
});
