/**
 * TAXII push tests — URL building + schema validation.
 * The actual HTTP push path needs a live remote; this covers the
 * non-network pieces.
 */
import { describe, it, expect } from 'vitest';
import { buildPushUrl } from '../services/taxiiPushClient';
import {
    TaxiiRemoteTargetCreateSchema,
    TaxiiRemoteTargetUpdateSchema,
} from '../lib/schemas';

describe('buildPushUrl', () => {
    it('appends /collections/<id>/objects/ to the api root', () => {
        const url = buildPushUrl('https://taxii.example.com/api/v2', 'rinjani-out');
        expect(url).toBe('https://taxii.example.com/api/v2/collections/rinjani-out/objects/');
    });

    it('strips a trailing slash on apiRoot to avoid double-slash', () => {
        const url = buildPushUrl('https://taxii.example.com/api/v2/', 'col-1');
        expect(url).toBe('https://taxii.example.com/api/v2/collections/col-1/objects/');
    });

    it('url-encodes collection ids with reserved characters', () => {
        const url = buildPushUrl('https://taxii.example.com/api/v2', 'space space');
        expect(url).toContain('collections/space%20space/objects/');
    });
});

describe('TaxiiRemoteTargetCreateSchema', () => {
    const valid = {
        name: 'OpenCTI lab',
        discoveryUrl: 'https://opencti.example.com/taxii2/',
        apiRoot: 'https://opencti.example.com/taxii2/v21',
        collectionId: 'rinjani-inbound',
    };

    it('accepts minimal valid payload', () => {
        const r = TaxiiRemoteTargetCreateSchema.parse(valid);
        expect(r.enabled).toBe(true);          // default
        expect(r.pushFilter).toEqual({});       // default
    });

    it('rejects missing required fields', () => {
        expect(() => TaxiiRemoteTargetCreateSchema.parse({ ...valid, name: '' })).toThrow();
        expect(() => TaxiiRemoteTargetCreateSchema.parse({ ...valid, apiRoot: 'not-a-url' })).toThrow();
    });

    it('accepts pushFilter with all bundle-export knobs', () => {
        const r = TaxiiRemoteTargetCreateSchema.parse({
            ...valid,
            pushFilter: {
                iocSource: 'threatfox',
                severity: 'critical',
                iocLimit: 5000,
                defaultTlp: 'green',
                includeIOCs: true,
                includeThreatActors: false,
                includeVulnerabilities: true,
            },
        });
        expect(r.pushFilter.defaultTlp).toBe('green');
        expect(r.pushFilter.includeThreatActors).toBe(false);
    });

    it('rejects invalid TLP values', () => {
        expect(() => TaxiiRemoteTargetCreateSchema.parse({
            ...valid,
            pushFilter: { defaultTlp: 'rainbow' },
        })).toThrow();
    });
});

describe('TaxiiRemoteTargetUpdateSchema', () => {
    it('makes every field optional', () => {
        const r = TaxiiRemoteTargetUpdateSchema.parse({ enabled: false });
        expect(r.enabled).toBe(false);
    });
});
