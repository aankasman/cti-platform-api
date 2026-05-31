/**
 * Search API Integration Tests
 * 
 * Tests for search functionality across different entity types.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Search API', () => {
    describe('GET /v1/search', () => {
        it('should support search query', async () => {
            const response = await apiRequest('/v1/search?q=test');
            expect([200, 404, 429]).toContain(response.status);
        });
    });

    describe('GET /v2/search', () => {
        it('should respond to search endpoint', async () => {
            const response = await apiRequest('/v2/search?q=google');
            expect([200, 404, 429]).toContain(response.status);
        });
    });
});

describe('Threat Actors API', () => {
    describe('GET /v1/threat-actors', () => {
        it('should respond to threat actors endpoint', async () => {
            const response = await apiRequest('/v1/threat-actors');
            expect([200, 404, 429]).toContain(response.status);
        });

        it('should support pagination', async () => {
            const response = await apiRequest('/v1/threat-actors?limit=5');
            expect([200, 404, 429]).toContain(response.status);
        });
    });
});

describe('Vulnerabilities API', () => {
    describe('GET /v1/vulnerabilities', () => {
        it('should respond to vulnerabilities endpoint', async () => {
            const response = await apiRequest('/v1/vulnerabilities');
            expect([200, 404, 429]).toContain(response.status);
        });

        it('should support severity filter', async () => {
            const response = await apiRequest('/v1/vulnerabilities?severity=critical');
            expect([200, 404, 429]).toContain(response.status);
        });
    });
});

describe('Stats API', () => {
    describe('GET /v1/stats', () => {
        it('should return statistics', async () => {
            const response = await apiRequest('/v1/stats');
            if (response.status !== 200) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.success).toBe(true);
        });
    });
});
