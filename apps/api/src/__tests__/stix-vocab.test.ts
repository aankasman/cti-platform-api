/**
 * STIX 2.1 vocab + Neo4j label/edge mapping locks.
 *
 * If you add a value to STIX_RELATIONSHIP_TYPES, you also need to add it
 * to the DB CHECK constraint in
 * `packages/db/drizzle/0045_relationship_type_check.sql` — these tests
 * remind reviewers to make both edits.
 */
import { describe, it, expect } from 'vitest';
import { STIX_RELATIONSHIP_TYPES, isKnownRelationshipType } from '@rinjani/core/stixVocab';
import { CreateRelationshipSchema } from '../lib/schemas';

describe('STIX_RELATIONSHIP_TYPES', () => {
    it('covers the STIX 2.1 §5.7 SRO common vocab', () => {
        const stix21 = [
            'uses', 'targets', 'attributed-to', 'mitigates', 'derived-from',
            'indicates', 'related-to', 'beacons-to', 'communicates-with',
            'exfiltrates-to', 'downloads', 'drops', 'exploits',
            'originates-from', 'characterizes', 'av-classification',
            'controls', 'delivers', 'hosts', 'owns', 'authored-by',
            'sub-technique-of', 'revoked-by', 'detects', 'impersonates',
        ];
        for (const t of stix21) {
            expect(STIX_RELATIONSHIP_TYPES).toContain(t);
        }
    });

    it('keeps `unknown` for the MITRE worker fallback', () => {
        expect(STIX_RELATIONSHIP_TYPES).toContain('unknown');
    });

    it('rejects unknown types via the type guard', () => {
        expect(isKnownRelationshipType('uses')).toBe(true);
        expect(isKnownRelationshipType('unfollows')).toBe(false);
        expect(isKnownRelationshipType('')).toBe(false);
    });
});

describe('CreateRelationshipSchema relationshipType enum', () => {
    const valid = {
        sourceType: 'ioc' as const,
        sourceId: 'abc',
        targetType: 'threat-actor' as const,
        targetId: 'apt28',
    };

    it('accepts every value in STIX_RELATIONSHIP_TYPES', () => {
        for (const t of STIX_RELATIONSHIP_TYPES) {
            const r = CreateRelationshipSchema.parse({ ...valid, relationshipType: t });
            expect(r.relationshipType).toBe(t);
        }
    });

    it('rejects a value not in the vocab', () => {
        expect(() => CreateRelationshipSchema.parse({ ...valid, relationshipType: 'eats' })).toThrow();
    });

    it('accepts the widened entity-type vocab (Phase 2 #1)', () => {
        const r = CreateRelationshipSchema.parse({
            sourceType: 'threat-actor',
            sourceId: 'apt28',
            targetType: 'infrastructure',
            targetId: 'c2-server-1',
            relationshipType: 'controls',
        });
        expect(r.targetType).toBe('infrastructure');
    });
});
