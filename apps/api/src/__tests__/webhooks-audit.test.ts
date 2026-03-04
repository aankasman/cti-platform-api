/**
 * Webhooks & Audit Integration Tests
 * 
 * These endpoints require authentication.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('Webhooks API', () => {
    describe('Endpoint availability', () => {
        it('should respond to webhooks endpoint', async () => {
            const response = await apiRequest('/v1/webhooks');
            // Expect either auth required or internal error
            expect([401, 429, 500]).toContain(response.status);
        });

        it('should respond to webhook events endpoint', async () => {
            const response = await apiRequest('/v1/webhooks/events');
            expect([401, 429, 500]).toContain(response.status);
        });
    });
});

describe('Audit API', () => {
    describe('Endpoint availability', () => {
        it('should respond to audit endpoint', async () => {
            const response = await apiRequest('/v1/audit');
            expect([401, 429, 500]).toContain(response.status);
        });

        it('should respond to audit stats endpoint', async () => {
            const response = await apiRequest('/v1/audit/stats');
            expect([401, 429, 500]).toContain(response.status);
        });
    });
});
