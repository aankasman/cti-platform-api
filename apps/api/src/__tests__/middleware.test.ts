/**
 * Middleware Tests
 * 
 * Tests for rate limiting, caching, and versioning middleware.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Rate Limiting Middleware', () => {
    describe('Rate Limit Headers', () => {
        it('should include rate limit headers on v1 endpoints', async () => {
            const response = await apiRequest('/v1/iocs');

            expect(response.headers.get('x-ratelimit-limit')).toBeTruthy();
            expect(response.headers.get('x-ratelimit-remaining')).toBeTruthy();
            expect(response.headers.get('x-ratelimit-reset')).toBeTruthy();
        });

        it('should include rate limit headers on v2 endpoints', async () => {
            const response = await apiRequest('/v2/stix/bundle?limit=1');

            expect(response.headers.get('x-ratelimit-limit')).toBeTruthy();
        });

        it('should track remaining requests', async () => {
            const response = await apiRequest('/v1/iocs?limit=1');
            const remaining = response.headers.get('x-ratelimit-remaining');
            expect(remaining).toBeTruthy();
        });
    });
});

describe('API Versioning Middleware', () => {
    describe('Version Headers', () => {
        it('should include API version header', async () => {
            const response = await apiRequest('/v2/stix');

            expect(response.headers.get('x-api-version')).toBe('2.0');
            expect(response.headers.get('x-api-min-version')).toBe('1.0');
        });

        it('should include deprecation notice on v1', async () => {
            const response = await apiRequest('/v1/iocs');

            expect(response.headers.get('deprecation')).toBe('true');
            expect(response.headers.get('x-deprecation-notice')).toBeTruthy();
        });

        it('should include sunset header on deprecated endpoints', async () => {
            const response = await apiRequest('/v1/iocs');

            const sunset = response.headers.get('sunset');
            expect(sunset).toBeTruthy();

            if (sunset) {
                const sunsetDate = new Date(sunset);
                expect(sunsetDate.getTime()).toBeGreaterThan(Date.now());
            }
        });

        it('should not include deprecation on v2', async () => {
            const response = await apiRequest('/v2/stix');

            expect(response.headers.get('deprecation')).toBeNull();
        });
    });
});

describe('Error Middleware', () => {
    describe('Error Response Format', () => {
        it('should return error for 404 endpoints', async () => {
            const response = await apiRequest('/v1/not-found');
            expect([404, 429, 500]).toContain(response.status);
        });
    });
});
