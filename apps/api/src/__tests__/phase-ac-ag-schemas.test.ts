/**
 * Phase AC–AG Schema Validation Tests
 *
 * Pure Zod schema tests — no running server required.
 * Covers all new schemas from the API improvement plan:
 *   - Phase AC: Feed management (sync trigger, history)
 *   - Phase AD: Indicator lifecycle (update, revoke, expire, verdict, sighting update)
 *   - Phase AE: Taxonomy & tag namespace
 *   - Phase AF: Enhanced export (MISP, rules, report)
 *   - Phase AG: CRUD completeness (threat actor, vulnerability, alert escalation)
 */

import { describe, it, expect } from 'vitest';
import {
    // Phase AC: Feed Management
    FeedSyncTriggerSchema,
    FeedSyncHistoryQuerySchema,
    // Phase AD: Indicator Lifecycle
    IOCUpdateSchema,
    IOCRevokeSchema,
    IOCExpireSchema,
    IOCVerdictSchema,
    SightingUpdateSchema,
    // Phase AE: Taxonomy
    CreateTaxonomySchema,
    AddTaxonomyTagSchema,
    // Phase AF: Enhanced Export
    MISPExportSchema,
    RuleExportSchema,
    ReportExportSchema,
    // Phase AG: CRUD Completeness
    CreateThreatActorSchema,
    UpdateThreatActorSchema,
    UpdateVulnerabilitySchema,
    VulnLinkIOCSchema,
    AlertEscalateSchema,
} from '../lib/schemas';

// ============================================================================
// Phase AC: Feed Management Enhancements
// ============================================================================

describe('FeedSyncTriggerSchema', () => {
    it('accepts empty body (defaults force=false)', () => {
        const result = FeedSyncTriggerSchema.parse({});
        expect(result.force).toBe(false);
    });
    it('accepts explicit force=true', () => {
        const result = FeedSyncTriggerSchema.parse({ force: true });
        expect(result.force).toBe(true);
    });
});

describe('FeedSyncHistoryQuerySchema', () => {
    it('defaults limit to 20', () => {
        const result = FeedSyncHistoryQuerySchema.parse({});
        expect(result.limit).toBe(20);
    });
    it('accepts custom limit', () => {
        const result = FeedSyncHistoryQuerySchema.parse({ limit: '50' });
        expect(result.limit).toBe(50);
    });
    it('rejects limit > 100', () => {
        expect(() => FeedSyncHistoryQuerySchema.parse({ limit: '200' })).toThrow();
    });
});

// ============================================================================
// Phase AD: Indicator Lifecycle Management
// ============================================================================

describe('IOCUpdateSchema', () => {
    it('accepts partial update with severity', () => {
        const result = IOCUpdateSchema.parse({ severity: 'critical' });
        expect(result.severity).toBe('critical');
    });
    it('accepts update with confidence + tags', () => {
        const result = IOCUpdateSchema.parse({ confidence: 85, tags: ['apt', 'banking'] });
        expect(result.confidence).toBe(85);
        expect(result.tags).toEqual(['apt', 'banking']);
    });
    it('rejects empty object', () => {
        expect(() => IOCUpdateSchema.parse({})).toThrow();
    });
    it('rejects invalid severity', () => {
        expect(() => IOCUpdateSchema.parse({ severity: 'banana' })).toThrow();
    });
    it('rejects confidence > 100', () => {
        expect(() => IOCUpdateSchema.parse({ confidence: 150 })).toThrow();
    });
    it('accepts notes field', () => {
        const result = IOCUpdateSchema.parse({ notes: 'This IOC was verified by analyst' });
        expect(result.notes).toContain('verified');
    });
});

describe('IOCRevokeSchema', () => {
    it('requires reason', () => {
        expect(() => IOCRevokeSchema.parse({})).toThrow();
    });
    it('accepts valid reason', () => {
        const result = IOCRevokeSchema.parse({ reason: 'False positive confirmed by vendor' });
        expect(result.reason).toContain('False positive');
    });
    it('rejects empty reason', () => {
        expect(() => IOCRevokeSchema.parse({ reason: '' })).toThrow();
    });
});

describe('IOCExpireSchema', () => {
    it('accepts valid ISO datetime', () => {
        const result = IOCExpireSchema.parse({ validUntil: '2025-12-31T23:59:59Z' });
        expect(result.validUntil).toBe('2025-12-31T23:59:59Z');
    });
    it('rejects invalid date format', () => {
        expect(() => IOCExpireSchema.parse({ validUntil: 'next-week' })).toThrow();
    });
});

describe('IOCVerdictSchema', () => {
    it('accepts malicious verdict', () => {
        const result = IOCVerdictSchema.parse({ verdict: 'malicious' });
        expect(result.verdict).toBe('malicious');
    });
    it('accepts all verdict values', () => {
        for (const v of ['malicious', 'suspicious', 'benign', 'unknown']) {
            expect(IOCVerdictSchema.parse({ verdict: v }).verdict).toBe(v);
        }
    });
    it('accepts verdict with notes', () => {
        const result = IOCVerdictSchema.parse({ verdict: 'suspicious', notes: 'Needs further investigation' });
        expect(result.notes).toContain('investigation');
    });
    it('rejects invalid verdict', () => {
        expect(() => IOCVerdictSchema.parse({ verdict: 'maybe' })).toThrow();
    });
});

describe('SightingUpdateSchema', () => {
    it('accepts partial source update', () => {
        const result = SightingUpdateSchema.parse({ source: 'honeypot-eu-01' });
        expect(result.source).toBe('honeypot-eu-01');
    });
    it('accepts type change to false-positive', () => {
        const result = SightingUpdateSchema.parse({ type: 'false-positive' });
        expect(result.type).toBe('false-positive');
    });
    it('rejects empty object', () => {
        expect(() => SightingUpdateSchema.parse({})).toThrow();
    });
});

// ============================================================================
// Phase AE: Taxonomy & Tag Namespace
// ============================================================================

describe('CreateTaxonomySchema', () => {
    it('accepts valid taxonomy', () => {
        const result = CreateTaxonomySchema.parse({
            namespace: 'custom-industry',
            name: 'Custom Industry Classification',
        });
        expect(result.namespace).toBe('custom-industry');
        expect(result.exclusive).toBe(false);
    });
    it('rejects namespace with uppercase', () => {
        expect(() => CreateTaxonomySchema.parse({ namespace: 'InvalidName', name: 'Test' })).toThrow();
    });
    it('rejects namespace with spaces', () => {
        expect(() => CreateTaxonomySchema.parse({ namespace: 'has spaces', name: 'Test' })).toThrow();
    });
    it('accepts exclusive=true', () => {
        const result = CreateTaxonomySchema.parse({
            namespace: 'severity', name: 'Severity', exclusive: true,
        });
        expect(result.exclusive).toBe(true);
    });
});

describe('AddTaxonomyTagSchema', () => {
    it('accepts tag with colour', () => {
        const result = AddTaxonomyTagSchema.parse({
            tag: 'high', description: 'High severity', colour: '#FF0000',
        });
        expect(result.colour).toBe('#FF0000');
    });
    it('rejects invalid colour format', () => {
        expect(() => AddTaxonomyTagSchema.parse({
            tag: 'test', colour: 'red',
        })).toThrow();
    });
    it('accepts numeric value', () => {
        const result = AddTaxonomyTagSchema.parse({
            tag: 'medium', numericValue: 50,
        });
        expect(result.numericValue).toBe(50);
    });
});

// ============================================================================
// Phase AF: Enhanced Export
// ============================================================================

describe('MISPExportSchema', () => {
    it('defaults to iocs and green TLP', () => {
        const result = MISPExportSchema.parse({});
        expect(result.entityTypes).toEqual(['iocs']);
        expect(result.tlp).toBe('green');
        expect(result.limit).toBe(1000);
    });
    it('accepts multiple entity types', () => {
        const result = MISPExportSchema.parse({
            entityTypes: ['iocs', 'vulnerabilities', 'threat-actors'],
            tlp: 'amber',
        });
        expect(result.entityTypes).toHaveLength(3);
    });
    it('accepts date range', () => {
        const result = MISPExportSchema.parse({
            dateFrom: '2025-01-01', dateTo: '2025-03-01',
        });
        expect(result.dateFrom).toBe('2025-01-01');
    });
});

describe('RuleExportSchema', () => {
    it('requires format (suricata or snort)', () => {
        expect(() => RuleExportSchema.parse({})).toThrow();
    });
    it('accepts suricata with custom action', () => {
        const result = RuleExportSchema.parse({
            format: 'suricata', action: 'drop',
        });
        expect(result.format).toBe('suricata');
        expect(result.action).toBe('drop');
    });
    it('defaults sid_start to 9000000', () => {
        const result = RuleExportSchema.parse({ format: 'snort' });
        expect(result.sid_start).toBe(9000000);
    });
    it('accepts specific IOC types', () => {
        const result = RuleExportSchema.parse({
            format: 'suricata', iocTypes: ['ip', 'domain'],
        });
        expect(result.iocTypes).toEqual(['ip', 'domain']);
    });
});

describe('ReportExportSchema', () => {
    it('defaults to markdown summary', () => {
        const result = ReportExportSchema.parse({});
        expect(result.format).toBe('markdown');
        expect(result.scope).toBe('summary');
    });
    it('accepts full scope with html', () => {
        const result = ReportExportSchema.parse({
            format: 'html', scope: 'full',
        });
        expect(result.format).toBe('html');
        expect(result.scope).toBe('full');
    });
});

// ============================================================================
// Phase AG: CRUD Completeness
// ============================================================================

describe('CreateThreatActorSchema', () => {
    it('requires name', () => {
        expect(() => CreateThreatActorSchema.parse({})).toThrow();
    });
    it('accepts minimal actor', () => {
        const result = CreateThreatActorSchema.parse({ name: 'APT29' });
        expect(result.name).toBe('APT29');
        expect(result.aliases).toEqual([]);
    });
    it('accepts full actor profile', () => {
        const result = CreateThreatActorSchema.parse({
            name: 'APT28',
            description: 'Russian GRU-linked threat group',
            aliases: ['Fancy Bear', 'Sofacy'],
            sophistication: 'expert',
            resourceLevel: 'government',
            primaryMotivation: 'political',
            tags: ['russia', 'espionage'],
        });
        expect(result.aliases).toHaveLength(2);
        expect(result.sophistication).toBe('expert');
        expect(result.resourceLevel).toBe('government');
    });
    it('rejects invalid sophistication level', () => {
        expect(() => CreateThreatActorSchema.parse({
            name: 'Test', sophistication: 'ultra-mega',
        })).toThrow();
    });
});

describe('UpdateThreatActorSchema', () => {
    it('rejects empty update', () => {
        expect(() => UpdateThreatActorSchema.parse({})).toThrow();
    });
    it('accepts partial name update', () => {
        const result = UpdateThreatActorSchema.parse({ name: 'APT29 (Cozy Bear)' });
        expect(result.name).toBe('APT29 (Cozy Bear)');
    });
});

describe('UpdateVulnerabilitySchema', () => {
    it('accepts severity override', () => {
        const result = UpdateVulnerabilitySchema.parse({ severity: 'critical' });
        expect(result.severity).toBe('critical');
    });
    it('accepts exploited flag', () => {
        const result = UpdateVulnerabilitySchema.parse({ exploited: true });
        expect(result.exploited).toBe(true);
    });
    it('rejects empty update', () => {
        expect(() => UpdateVulnerabilitySchema.parse({})).toThrow();
    });
});

describe('VulnLinkIOCSchema', () => {
    it('requires valid UUID for iocId', () => {
        expect(() => VulnLinkIOCSchema.parse({ iocId: 'not-a-uuid' })).toThrow();
    });
    it('accepts valid link with relationship', () => {
        const result = VulnLinkIOCSchema.parse({
            iocId: '550e8400-e29b-41d4-a716-446655440000',
            relationship: 'exploits',
        });
        expect(result.relationship).toBe('exploits');
    });
    it('defaults relationship to related-to', () => {
        const result = VulnLinkIOCSchema.parse({
            iocId: '550e8400-e29b-41d4-a716-446655440000',
        });
        expect(result.relationship).toBe('related-to');
    });
});

describe('AlertEscalateSchema', () => {
    it('defaults priority to medium', () => {
        const result = AlertEscalateSchema.parse({});
        expect(result.priority).toBe('medium');
        expect(result.tags).toEqual([]);
    });
    it('accepts full escalation', () => {
        const result = AlertEscalateSchema.parse({
            priority: 'critical',
            assignee: 'security-team-lead',
            notes: 'Requires immediate attention — active exploitation detected',
            tags: ['p0', 'active-exploit'],
        });
        expect(result.priority).toBe('critical');
        expect(result.tags).toHaveLength(2);
    });
});
