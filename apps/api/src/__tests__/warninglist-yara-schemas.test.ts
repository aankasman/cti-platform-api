/**
 * Phase R — Warninglist, YARA, and Playbook Execute Schema Tests
 *
 * Validates all 9 new Zod schemas added in Phase R.
 */

import { describe, it, expect } from 'vitest';
import {
    CreateWarninglistSchema,
    UpdateWarninglistSchema,
    WarninglistEntriesSchema,
    WarninglistCheckSchema,
    AddYaraRuleSchema,
    ToggleYaraRuleSchema,
    YaraScanSchema,
    YaraBatchScanSchema,
    ExecutePlaybookSchema,
} from '../lib/schemas';

// ============================================================================
// Warninglist Schemas
// ============================================================================

describe('CreateWarninglistSchema', () => {
    it('accepts valid create payload', () => {
        const result = CreateWarninglistSchema.parse({
            name: 'RFC1918 Networks',
            type: 'cidr',
            description: 'Private IPv4 ranges',
            entries: ['10.0.0.0/8', '172.16.0.0/12'],
        });
        expect(result.name).toBe('RFC1918 Networks');
        expect(result.type).toBe('cidr');
        expect(result.entries).toHaveLength(2);
    });

    it('rejects missing name', () => {
        expect(() =>
            CreateWarninglistSchema.parse({ type: 'string' })
        ).toThrow();
    });

    it('rejects invalid type', () => {
        expect(() =>
            CreateWarninglistSchema.parse({ name: 'Test', type: 'invalid' })
        ).toThrow();
    });

    it('accepts all valid types', () => {
        for (const t of ['cidr', 'hostname', 'string', 'regex']) {
            const res = CreateWarninglistSchema.parse({ name: 'T', type: t });
            expect(res.type).toBe(t);
        }
    });

    it('allows optional fields to be omitted', () => {
        const res = CreateWarninglistSchema.parse({ name: 'N', type: 'string' });
        expect(res.description).toBeUndefined();
        expect(res.entries).toBeUndefined();
    });
});

describe('UpdateWarninglistSchema', () => {
    it('accepts partial update', () => {
        const res = UpdateWarninglistSchema.parse({ name: 'Updated Name', enabled: false });
        expect(res.name).toBe('Updated Name');
        expect(res.enabled).toBe(false);
    });

    it('accepts empty object (no changes)', () => {
        const res = UpdateWarninglistSchema.parse({});
        expect(Object.keys(res)).toHaveLength(0);
    });
});

describe('WarninglistEntriesSchema', () => {
    it('accepts valid entries array', () => {
        const res = WarninglistEntriesSchema.parse({ values: ['a', 'b', 'c'] });
        expect(res.values).toHaveLength(3);
    });

    it('rejects empty array', () => {
        expect(() =>
            WarninglistEntriesSchema.parse({ values: [] })
        ).toThrow();
    });

    it('rejects missing values', () => {
        expect(() =>
            WarninglistEntriesSchema.parse({})
        ).toThrow();
    });
});

describe('WarninglistCheckSchema', () => {
    it('accepts valid check payload', () => {
        const res = WarninglistCheckSchema.parse({ value: '1.2.3.4', type: 'cidr' });
        expect(res.value).toBe('1.2.3.4');
        expect(res.type).toBe('cidr');
    });

    it('rejects empty value', () => {
        expect(() =>
            WarninglistCheckSchema.parse({ value: '' })
        ).toThrow();
    });

    it('allows omitting type', () => {
        const res = WarninglistCheckSchema.parse({ value: 'example.com' });
        expect(res.type).toBeUndefined();
    });
});

// ============================================================================
// YARA Schemas
// ============================================================================

describe('AddYaraRuleSchema', () => {
    const validRule = {
        name: 'test_rule',
        strings: [{ id: '$s1', value: 'malware', type: 'text' }],
        condition: 'any of them',
    };

    it('accepts valid rule with defaults', () => {
        const res = AddYaraRuleSchema.parse(validRule);
        expect(res.name).toBe('test_rule');
        expect(res.description).toBe('');
        expect(res.author).toBe('API');
        expect(res.tags).toEqual([]);
        expect(res.severity).toBe('medium');
        expect(res.enabled).toBe(true);
    });

    it('rejects invalid name', () => {
        expect(() =>
            AddYaraRuleSchema.parse({ ...validRule, name: 'bad name!' })
        ).toThrow();
    });

    it('rejects missing strings', () => {
        expect(() =>
            AddYaraRuleSchema.parse({ name: 'r1', condition: 'any of them' })
        ).toThrow();
    });

    it('rejects empty strings array', () => {
        expect(() =>
            AddYaraRuleSchema.parse({ ...validRule, strings: [] })
        ).toThrow();
    });

    it('rejects missing condition', () => {
        expect(() =>
            AddYaraRuleSchema.parse({ name: 'r1', strings: [{ id: '$s1', value: 'x' }] })
        ).toThrow();
    });

    it('accepts all severity levels', () => {
        for (const s of ['critical', 'high', 'medium', 'low', 'info']) {
            const res = AddYaraRuleSchema.parse({ ...validRule, severity: s });
            expect(res.severity).toBe(s);
        }
    });

    it('applies defaults to string modifiers', () => {
        const res = AddYaraRuleSchema.parse(validRule);
        expect(res.strings[0].modifiers).toEqual([]);
    });
});

describe('ToggleYaraRuleSchema', () => {
    it('accepts {enabled: true}', () => {
        const res = ToggleYaraRuleSchema.parse({ enabled: true });
        expect(res.enabled).toBe(true);
    });

    it('accepts {enabled: false}', () => {
        const res = ToggleYaraRuleSchema.parse({ enabled: false });
        expect(res.enabled).toBe(false);
    });

    it('rejects missing enabled', () => {
        expect(() =>
            ToggleYaraRuleSchema.parse({})
        ).toThrow();
    });

    it('rejects non-boolean enabled', () => {
        expect(() =>
            ToggleYaraRuleSchema.parse({ enabled: 'yes' })
        ).toThrow();
    });
});

describe('YaraScanSchema', () => {
    it('accepts valid scan input', () => {
        const res = YaraScanSchema.parse({ value: 'suspicious.tk' });
        expect(res.value).toBe('suspicious.tk');
    });

    it('rejects empty value', () => {
        expect(() =>
            YaraScanSchema.parse({ value: '' })
        ).toThrow();
    });

    it('rejects missing value', () => {
        expect(() =>
            YaraScanSchema.parse({})
        ).toThrow();
    });
});

describe('YaraBatchScanSchema', () => {
    it('accepts valid batch', () => {
        const res = YaraBatchScanSchema.parse({ values: ['a.tk', 'b.ml'] });
        expect(res.values).toHaveLength(2);
    });

    it('rejects empty array', () => {
        expect(() =>
            YaraBatchScanSchema.parse({ values: [] })
        ).toThrow();
    });

    it('rejects oversized batch', () => {
        const bigArray = Array.from({ length: 10001 }, (_, i) => `v${i}`);
        expect(() =>
            YaraBatchScanSchema.parse({ values: bigArray })
        ).toThrow();
    });

    it('accepts exactly 10000 values', () => {
        const arr = Array.from({ length: 10000 }, (_, i) => `v${i}`);
        const res = YaraBatchScanSchema.parse({ values: arr });
        expect(res.values).toHaveLength(10000);
    });
});

// ============================================================================
// Playbook Execute Schema
// ============================================================================

describe('ExecutePlaybookSchema', () => {
    it('accepts valid trigger data', () => {
        const res = ExecutePlaybookSchema.parse({ triggerData: { iocId: '123' } });
        expect(res.triggerData).toEqual({ iocId: '123' });
    });

    it('defaults triggerData to empty object', () => {
        const res = ExecutePlaybookSchema.parse({});
        expect(res.triggerData).toEqual({});
    });

    it('accepts empty trigger data', () => {
        const res = ExecutePlaybookSchema.parse({ triggerData: {} });
        expect(res.triggerData).toEqual({});
    });
});
