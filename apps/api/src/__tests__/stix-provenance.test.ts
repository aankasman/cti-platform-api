/**
 * STIX provenance wiring tests.
 *
 * Locks the behavior added by Phase 2 item #5: every exported object
 * carries created_by_ref, object_marking_refs, confidence, and the
 * `extension-definition--provenance` block, and TLP defaults derive
 * from the source.
 */
import { describe, it, expect } from 'vitest';
import {
    buildProvenance,
    SOURCE_IDENTITIES,
    TLP_MARKINGS,
    PLATFORM_IDENTITY,
} from '@rinjani/core/stixProvenance';

describe('buildProvenance', () => {
    it('returns the producer identity as created_by_ref', () => {
        const p = buildProvenance('virustotal', 80, 'green');
        expect(p.created_by_ref).toBe(SOURCE_IDENTITIES.virustotal.id);
    });

    it('synthesises an identity for unknown sources', () => {
        const p = buildProvenance('some-new-feed', 50, 'white');
        expect(p.created_by_ref).toBe('identity--some-new-feed');
    });

    it('emits the correct TLP marking ref', () => {
        const p = buildProvenance('alienvault', 50, 'amber');
        expect(p.object_marking_refs).toEqual([TLP_MARKINGS.amber.id]);
    });

    it('falls back to TLP:WHITE on bogus input', () => {
        const p = buildProvenance('alienvault', 50, 'rainbow');
        expect(p.object_marking_refs).toEqual([TLP_MARKINGS.white.id]);
    });

    it('emits the provenance extension with the primary source + initial merge event', () => {
        const p = buildProvenance('threatfox', 65, 'white');
        const ext = p.extensions?.['extension-definition--provenance'];
        expect(ext).toBeDefined();
        expect(ext!.sources).toHaveLength(1);
        expect(ext!.sources[0]).toMatchObject({
            source_name: 'threatfox',
            source_type: 'feed',
            confidence: 65,
        });
        expect(ext!.merge_history[0]).toMatchObject({
            action: 'created',
            source: 'threatfox',
        });
    });

    it('sets data_quality.corroboration to 1 when no additional sources provided', () => {
        const p = buildProvenance('threatfox', 65, 'white');
        const ext = p.extensions?.['extension-definition--provenance']!;
        expect(ext.data_quality.corroboration).toBe(1);
    });

    it('sets data_quality.corroboration to 1 + additionalSources count', () => {
        const p = buildProvenance('threatfox', 65, 'white', [
            { source_name: 'urlhaus', source_type: 'feed', identity_ref: 'identity--urlhaus',
              first_observed: null, last_observed: null, confidence: 70, external_references: [] },
            { source_name: 'misp', source_type: 'feed', identity_ref: 'identity--misp',
              first_observed: null, last_observed: null, confidence: 60, external_references: [] },
        ]);
        const ext = p.extensions?.['extension-definition--provenance']!;
        expect(ext.sources).toHaveLength(3);
        expect(ext.data_quality.corroboration).toBe(3);
    });
});

describe('TLP_MARKINGS catalogue', () => {
    it('uses the canonical STIX 2.1 ids', () => {
        // From https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_yd3ar14ekwrs
        expect(TLP_MARKINGS.white.id).toBe('marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9');
        expect(TLP_MARKINGS.green.id).toBe('marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da');
        expect(TLP_MARKINGS.amber.id).toBe('marking-definition--f88d31f6-486f-44da-b317-01333bde0b82');
        expect(TLP_MARKINGS.red.id).toBe('marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed');
    });
});

describe('PLATFORM_IDENTITY', () => {
    it('is named consistently', () => {
        expect(PLATFORM_IDENTITY.name).toMatch(/Rinjani/i);
        expect(PLATFORM_IDENTITY.identity_class).toBe('system');
    });
});
