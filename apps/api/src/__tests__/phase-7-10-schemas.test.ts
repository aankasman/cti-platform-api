/**
 * Schema Validation Tests — Wave 2 (Phases 7–9)
 *
 * Pure Zod schema validation tests.
 * No running server or database required.
 */

import { describe, it, expect } from 'vitest';
import {
    CreateCaseSchema, UpdateCaseSchema, CaseFilterSchema,
    CaseObservableSchema, CaseTaskSchema, UpdateCaseTaskSchema,
    CaseTimelineSchema, CaseFromAlertSchema,
    ReputationReportSchema, BulkReputationSchema,
    RunAnalyzerSchema, ScanChainSchema,
} from '../lib/schemas';

// ============================================================================
// Phase 7: Case Management
// ============================================================================

describe('CreateCaseSchema', () => {
    it('requires title', () => {
        expect(() => CreateCaseSchema.parse({})).toThrow();
    });

    it('accepts minimal case', () => {
        const result = CreateCaseSchema.parse({ title: 'APT29 Investigation' });
        expect(result.title).toBe('APT29 Investigation');
        expect(result.severity).toBe('medium');
        expect(result.status).toBe('open');
        expect(result.tlp).toBe('green');
        expect(result.tags).toEqual([]);
    });

    it('accepts full case profile', () => {
        const result = CreateCaseSchema.parse({
            title: 'Phishing Campaign Q1',
            description: 'Multiple phishing emails targeting finance dept',
            severity: 'critical',
            status: 'in-progress',
            assignee: 'analyst-1',
            tlp: 'amber',
            tags: ['phishing', 'finance', 'urgent'],
        });
        expect(result.severity).toBe('critical');
        expect(result.tlp).toBe('amber');
        expect(result.tags).toHaveLength(3);
    });

    it('rejects invalid severity', () => {
        expect(() => CreateCaseSchema.parse({ title: 'Test', severity: 'extreme' })).toThrow();
    });
});

describe('UpdateCaseSchema', () => {
    it('rejects empty update', () => {
        expect(() => UpdateCaseSchema.parse({})).toThrow();
    });

    it('accepts partial status update', () => {
        const result = UpdateCaseSchema.parse({ status: 'resolved', resolution: 'Confirmed false positive' });
        expect(result.status).toBe('resolved');
    });

    it('accepts severity change', () => {
        const result = UpdateCaseSchema.parse({ severity: 'critical' });
        expect(result.severity).toBe('critical');
    });
});

describe('CaseFilterSchema', () => {
    it('has sensible defaults', () => {
        const result = CaseFilterSchema.parse({});
        expect(result.page).toBe(1);
        expect(result.pageSize).toBe(20);
    });

    it('accepts all filter combinations', () => {
        const result = CaseFilterSchema.parse({
            page: '2', pageSize: '50', status: 'open', severity: 'high', q: 'phishing',
        });
        expect(result.page).toBe(2);
        expect(result.status).toBe('open');
    });
});

describe('CaseObservableSchema', () => {
    it('requires entity type and ID', () => {
        expect(() => CaseObservableSchema.parse({})).toThrow();
    });

    it('accepts IOC observable', () => {
        const result = CaseObservableSchema.parse({
            entityType: 'ioc', entityId: '123abc',
            notes: 'Suspicious IP', tags: ['suspicious'],
        });
        expect(result.entityType).toBe('ioc');
    });

    it('accepts vulnerability observable', () => {
        const result = CaseObservableSchema.parse({
            entityType: 'vulnerability', entityId: 'CVE-2024-1234',
        });
        expect(result.entityType).toBe('vulnerability');
    });
});

describe('CaseTaskSchema', () => {
    it('requires title', () => {
        expect(() => CaseTaskSchema.parse({})).toThrow();
    });

    it('accepts task with defaults', () => {
        const result = CaseTaskSchema.parse({ title: 'Analyze malware sample' });
        expect(result.status).toBe('todo');
    });

    it('accepts full task', () => {
        const result = CaseTaskSchema.parse({
            title: 'Check IP on VT',
            description: 'Run VirusTotal lookup',
            status: 'in-progress',
            assignee: 'analyst-2',
            dueDate: '2026-03-10T00:00:00Z',
        });
        expect(result.assignee).toBe('analyst-2');
    });
});

describe('UpdateCaseTaskSchema', () => {
    it('rejects empty update', () => {
        expect(() => UpdateCaseTaskSchema.parse({})).toThrow();
    });

    it('accepts status change', () => {
        const result = UpdateCaseTaskSchema.parse({ status: 'done' });
        expect(result.status).toBe('done');
    });
});

describe('CaseTimelineSchema', () => {
    it('requires content', () => {
        expect(() => CaseTimelineSchema.parse({})).toThrow();
    });

    it('defaults to comment type', () => {
        const result = CaseTimelineSchema.parse({ content: 'Found additional C2 domains' });
        expect(result.entryType).toBe('comment');
    });
});

describe('CaseFromAlertSchema', () => {
    it('accepts empty body', () => {
        const result = CaseFromAlertSchema.parse({});
        expect(result.tags).toEqual([]);
    });

    it('accepts title override', () => {
        const result = CaseFromAlertSchema.parse({ title: 'Custom Case Title', assignee: 'analyst-3' });
        expect(result.title).toBe('Custom Case Title');
    });
});

// ============================================================================
// Phase 8: Reputation
// ============================================================================

describe('ReputationReportSchema', () => {
    it('requires value and type', () => {
        expect(() => ReputationReportSchema.parse({})).toThrow();
    });

    it('accepts minimal report', () => {
        const result = ReputationReportSchema.parse({
            value: '192.168.1.100', type: 'ip',
        });
        expect(result.confidence).toBe(70);
        expect(result.ttlHours).toBe(720); // 30 days
        expect(result.category).toBe('other');
    });

    it('accepts full report', () => {
        const result = ReputationReportSchema.parse({
            value: 'evil.example.com', type: 'domain',
            category: 'c2', confidence: 95,
            notes: 'Known C2 server', ttlHours: 168,
        });
        expect(result.category).toBe('c2');
        expect(result.ttlHours).toBe(168);
    });

    it('rejects invalid type', () => {
        expect(() => ReputationReportSchema.parse({ value: 'x', type: 'unknown-type' })).toThrow();
    });
});

describe('BulkReputationSchema', () => {
    it('requires at least one value', () => {
        expect(() => BulkReputationSchema.parse({ values: [] })).toThrow();
    });

    it('accepts multiple values with auto type', () => {
        const result = BulkReputationSchema.parse({
            values: ['8.8.8.8', 'evil.com', 'test@phish.com'],
        });
        expect(result.values).toHaveLength(3);
        expect(result.type).toBe('auto');
    });

    it('enforces max 100 values', () => {
        const values = Array.from({ length: 101 }, (_, i) => `value-${i}`);
        expect(() => BulkReputationSchema.parse({ values })).toThrow();
    });
});

// ============================================================================
// Phase 9: Analyzers
// ============================================================================

describe('RunAnalyzerSchema', () => {
    it('requires value and analyzers', () => {
        expect(() => RunAnalyzerSchema.parse({})).toThrow();
    });

    it('accepts minimal run', () => {
        const result = RunAnalyzerSchema.parse({
            value: '8.8.8.8', analyzers: ['risk-score'],
        });
        expect(result.type).toBe('auto');
        expect(result.analyzers).toEqual(['risk-score']);
    });

    it('accepts multiple analyzers', () => {
        const result = RunAnalyzerSchema.parse({
            value: 'evil.com', type: 'domain',
            analyzers: ['risk-score', 'correlation', 'reputation'],
        });
        expect(result.analyzers).toHaveLength(3);
    });

    it('enforces max 20 analyzers', () => {
        const analyzers = Array.from({ length: 21 }, (_, i) => `analyzer-${i}`);
        expect(() => RunAnalyzerSchema.parse({ value: 'x', analyzers })).toThrow();
    });
});

describe('ScanChainSchema', () => {
    it('requires value and chain', () => {
        expect(() => ScanChainSchema.parse({})).toThrow();
    });

    it('defaults stopOnMalicious to false', () => {
        const result = ScanChainSchema.parse({
            value: '8.8.8.8', chain: ['risk-score', 'correlation'],
        });
        expect(result.stopOnMalicious).toBe(false);
    });

    it('accepts full chain config', () => {
        const result = ScanChainSchema.parse({
            value: 'evil.com', type: 'domain',
            chain: ['reputation', 'risk-score', 'yara-scan'],
            stopOnMalicious: true,
        });
        expect(result.stopOnMalicious).toBe(true);
        expect(result.chain).toHaveLength(3);
    });

    it('enforces max 10 chain steps', () => {
        const chain = Array.from({ length: 11 }, (_, i) => `step-${i}`);
        expect(() => ScanChainSchema.parse({ value: 'x', chain })).toThrow();
    });
});
