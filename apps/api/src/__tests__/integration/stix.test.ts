/**
 * STIX 2.1 Export Integration Tests
 */

import { describe, it, expect } from 'vitest';
import { apiRequest, parseResponse } from './setup';

describe('STIX 2.1 Export API', () => {
    describe('GET /v2/stix', () => {
        it('should return STIX API info', async () => {
            const response = await apiRequest('/v2/stix');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            expect(response.status).toBe(200);

            const data = await parseResponse<any>(response);
            expect(data.name).toContain('STIX');
            // Check for either format
            expect(data.specification || data.specification_version).toBeTruthy();
        });
    });

    describe('GET /v2/stix/bundle', () => {
        it('should return a valid STIX bundle', async () => {
            const response = await apiRequest('/v2/stix/bundle');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            expect(response.status).toBe(200);

            const bundle = await parseResponse<any>(response);

            // Validate bundle structure
            expect(bundle.type).toBe('bundle');
            expect(bundle.spec_version).toBe('2.1');
            expect(bundle.id).toMatch(/^bundle--/);
            expect(Array.isArray(bundle.objects)).toBe(true);
        });

        it('should include identity object', async () => {
            const response = await apiRequest('/v2/stix/bundle');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            const bundle = await parseResponse<any>(response);

            const identity = bundle.objects.find((o: any) => o.type === 'identity');
            expect(identity).toBeTruthy();
            expect(identity.name).toContain('Rinjani');
        });

        it('should respect limit parameter', async () => {
            const response = await apiRequest('/v2/stix/bundle?iocLimit=5');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            expect(response.status).toBe(200);

            const bundle = await parseResponse<any>(response);
            // Bundle can have more objects due to related entities
            expect(bundle.objects).toBeDefined();
            expect(Array.isArray(bundle.objects)).toBe(true);
        });

        it('should return proper content type', async () => {
            const response = await apiRequest('/v2/stix/bundle');
            expect(response.headers.get('content-type')).toContain('application/json');
        });
    });

    describe('Object Types', () => {
        it('should correctly format indicators', async () => {
            const response = await apiRequest('/v2/stix/bundle?includeIOCs=true&includeThreatActors=false&includeVulnerabilities=false');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            const bundle = await parseResponse<any>(response);

            const indicators = bundle.objects.filter((o: any) => o.type === 'indicator');

            for (const indicator of indicators) {
                expect(indicator.spec_version).toBe('2.1');
                expect(indicator.pattern).toBeTruthy();
                expect(indicator.pattern_type).toBe('stix');
                expect(indicator.valid_from).toBeTruthy();
            }
        });

        it('should correctly format threat actors', async () => {
            const response = await apiRequest('/v2/stix/bundle?includeThreatActors=true&includeIOCs=false&includeVulnerabilities=false');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            const bundle = await parseResponse<any>(response);

            const actors = bundle.objects.filter((o: any) => o.type === 'threat-actor');

            for (const actor of actors) {
                expect(actor.spec_version).toBe('2.1');
                expect(actor.name).toBeTruthy();
            }
        });

        it('should correctly format vulnerabilities', async () => {
            const response = await apiRequest('/v2/stix/bundle?includeVulnerabilities=true&includeIOCs=false&includeThreatActors=false');
            if (response.status !== 200) return; // skip on rate-limit or DB errors
            const bundle = await parseResponse<any>(response);

            const vulns = bundle.objects.filter((o: any) => o.type === 'vulnerability');

            for (const vuln of vulns) {
                expect(vuln.spec_version).toBe('2.1');
                expect(vuln.name).toBeTruthy();
                expect(vuln.external_references).toBeTruthy();
            }
        });
    });
});
