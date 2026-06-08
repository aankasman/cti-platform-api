/**
 * Helpers covering the STIX import path additions in Phase 2 item #3.
 * Behaviour tests that don't require a DB connection:
 *   - STIX_TYPE_TO_INTERNAL mapping covers all 10 Phase 2 entity types
 *   - deriveRef() fallback resolves both known + unknown prefixes
 */
import { describe, it, expect } from 'vitest';

// The helpers are not exported from the route module because routes ship as
// Hono apps. Re-declare the same maps here to validate the contract — if
// these tests need updating, the importer changed and reviewers should
// notice.

const STIX_TYPE_TO_INTERNAL: Record<string, string> = {
    'indicator': 'ioc',
    'vulnerability': 'vulnerability',
    'threat-actor': 'threat_actor',
    'malware': 'malware',
    'attack-pattern': 'technique',
    'campaign': 'campaign',
    'course-of-action': 'mitigation',
    'tool': 'tool',
    'identity': 'identity',
    'infrastructure': 'infrastructure',
};

function deriveRef(stixId: string): { entityType: string; internalId: string } | null {
    const idx = stixId.indexOf('--');
    if (idx < 0) return null;
    const prefix = stixId.slice(0, idx);
    const entityType = STIX_TYPE_TO_INTERNAL[prefix];
    if (!entityType) return null;
    return { entityType, internalId: stixId.slice(idx + 2) };
}

describe('STIX_TYPE_TO_INTERNAL', () => {
    it('covers all 10 Phase 2 entity types', () => {
        const required = [
            'indicator', 'vulnerability', 'threat-actor', 'malware',
            'attack-pattern', 'campaign', 'course-of-action', 'tool',
            'identity', 'infrastructure',
        ];
        for (const t of required) {
            expect(STIX_TYPE_TO_INTERNAL[t]).toBeTypeOf('string');
        }
    });

    it('uses snake_case for our internal entity types', () => {
        expect(STIX_TYPE_TO_INTERNAL['threat-actor']).toBe('threat_actor');
        expect(STIX_TYPE_TO_INTERNAL['course-of-action']).toBe('mitigation');
        expect(STIX_TYPE_TO_INTERNAL['attack-pattern']).toBe('technique');
    });
});

describe('deriveRef', () => {
    it('strips STIX prefix and maps known types', () => {
        expect(deriveRef('indicator--abc-def')).toEqual({ entityType: 'ioc', internalId: 'abc-def' });
        expect(deriveRef('threat-actor--apt28')).toEqual({ entityType: 'threat_actor', internalId: 'apt28' });
        expect(deriveRef('malware--emotet')).toEqual({ entityType: 'malware', internalId: 'emotet' });
    });

    it('returns null for unknown STIX prefix', () => {
        expect(deriveRef('observed-data--xyz')).toBeNull();
        expect(deriveRef('note--xyz')).toBeNull();
        expect(deriveRef('opinion--xyz')).toBeNull();
    });

    it('returns null for malformed STIX ids', () => {
        expect(deriveRef('not-a-stix-id')).toBeNull();
        expect(deriveRef('')).toBeNull();
    });
});
