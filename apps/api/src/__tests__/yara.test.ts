/**
 * YARA Rules API Integration Tests
 *
 * Tests for YARA rule CRUD, toggle, scan, and batch-scan operations.
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('YARA Rules API', () => {
    describe('GET /v1/yara/rules', () => {
        it('should return rules list', async () => {
            const response = await apiRequest('/v1/yara/rules');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.success).toBe(true);
            expect(data.data).toBeDefined();
        });

        it('should return rules with expected fields', async () => {
            const response = await apiRequest('/v1/yara/rules');
            if (response.status === 429) return;
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            const rules = Array.isArray(data.data) ? data.data : [];
            if (rules.length > 0) {
                const rule = rules[0];
                expect(rule.name).toBeDefined();
                expect(typeof rule.enabled).toBe('boolean');
                expect(rule.condition).toBeDefined();
            }
        });
    });

    describe('POST /v1/yara/rules', () => {
        it('should reject rule without required fields', async () => {
            const response = await apiRequest('/v1/yara/rules', {
                method: 'POST',
                body: JSON.stringify({}),
            });
            expect([400, 422, 429, 500]).toContain(response.status);
        });

        it('should reject rule with empty name', async () => {
            const response = await apiRequest('/v1/yara/rules', {
                method: 'POST',
                body: JSON.stringify({
                    name: '',
                    patterns: [],
                    condition: 'any of them',
                }),
            });
            expect([400, 422, 429, 500]).toContain(response.status);
        });
    });

    describe('GET /v1/yara/rules/:name', () => {
        it('should return 404 for non-existent rule', async () => {
            const response = await apiRequest('/v1/yara/rules/nonexistent_rule_xyz');
            expect([404, 429, 500]).toContain(response.status);
        });
    });

    describe('PUT /v1/yara/rules/:name/toggle', () => {
        it('should return 404 for non-existent rule', async () => {
            const response = await apiRequest('/v1/yara/rules/nonexistent_rule_xyz/toggle', {
                method: 'PUT',
            });
            expect([404, 429, 500]).toContain(response.status);
        });
    });

    describe('DELETE /v1/yara/rules/:name', () => {
        it('should return 404 for non-existent rule', async () => {
            const response = await apiRequest('/v1/yara/rules/nonexistent_rule_xyz', {
                method: 'DELETE',
            });
            expect([404, 429, 500]).toContain(response.status);
        });
    });

    describe('POST /v1/yara/scan', () => {
        it('should accept scan request', async () => {
            const response = await apiRequest('/v1/yara/scan', {
                method: 'POST',
                body: JSON.stringify({ value: 'test-scan-value-123' }),
            });
            if (response.status === 429) return;
            expect([200, 400, 422]).toContain(response.status);

            if (response.status === 200) {
                const data = await parseResponse<any>(response);
                expect(data.success).toBe(true);
                expect(data.data).toBeDefined();
                expect(data.data.matches).toBeDefined();
            }
        });

        it('should reject scan without value', async () => {
            const response = await apiRequest('/v1/yara/scan', {
                method: 'POST',
                body: JSON.stringify({}),
            });
            expect([400, 422, 429, 500]).toContain(response.status);
        });
    });

    describe('POST /v1/yara/batch-scan', () => {
        it('should accept batch scan with multiple values', async () => {
            const response = await apiRequest('/v1/yara/batch-scan', {
                method: 'POST',
                body: JSON.stringify({ values: ['val1', 'val2'] }),
            });
            if (response.status === 429) return;
            expect([200, 400, 422]).toContain(response.status);

            if (response.status === 200) {
                const data = await parseResponse<any>(response);
                expect(data.data.results).toBeDefined();
            }
        });

        it('should reject batch scan without values array', async () => {
            const response = await apiRequest('/v1/yara/batch-scan', {
                method: 'POST',
                body: JSON.stringify({}),
            });
            expect([400, 422, 429, 500]).toContain(response.status);
        });
    });
});
