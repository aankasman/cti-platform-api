/**
 * Report ingestion service tests — Phase 3 #1 scaffold.
 *
 * The service composes a pure IOC extractor (covered in ioc-extractor.test.ts)
 * with an LLM helper. These tests verify the orchestration:
 *   - skipLlm short-circuits cleanly with iocs populated
 *   - LLM failure leaves iocs intact + reports llmError
 *   - text truncation honours MAX_TEXT_LEN
 *   - source field round-trips
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the LLM helper BEFORE importing the service.
vi.mock('../services/aiMiddleware/helpers', () => ({
    extractEntities: vi.fn(),
}));

import { ingestReportText } from '../services/reportIngestion';
import * as helpers from '../services/aiMiddleware/helpers';

const SAMPLE_REPORT = `
APT Forensic Note 2026-06-09

Attackers staged from 198.51.100.42 and the C2 domain evil[.]example was used.
File hashes observed:
  - SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  - MD5:     d41d8cd98f00b204e9800998ecf8427e
Exploited cve-2024-12345 to gain access. See report.pdf for the playbook.
Contact intel@rinjanianalytics.com for follow-up.
Drop URL: hxxps://evil[.]example/loader.sh
`.trim();

describe('ingestReportText — IOC extraction', () => {
    afterEach(() => vi.clearAllMocks());

    it('extracts IOCs even when LLM is skipped', async () => {
        const r = await ingestReportText({ text: SAMPLE_REPORT, skipLlm: true });
        expect(r.iocs.grouped.ipv4).toContain('198.51.100.42');
        expect(r.iocs.grouped.domain).toContain('evil.example');
        expect(r.iocs.grouped['hash-sha256']).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        expect(r.iocs.grouped['hash-md5']).toContain('d41d8cd98f00b204e9800998ecf8427e');
        expect(r.iocs.grouped.cve).toContain('CVE-2024-12345');
        expect(r.iocs.grouped.email).toContain('intel@rinjanianalytics.com');
        expect(r.iocs.grouped.url).toContain('https://evil.example/loader.sh');
        // report.pdf must NOT leak in as a domain
        expect(r.iocs.grouped.domain).not.toContain('report.pdf');
    });

    it('does not call the LLM when skipLlm=true', async () => {
        await ingestReportText({ text: 'hello 1.2.3.4', skipLlm: true });
        expect(helpers.extractEntities).not.toHaveBeenCalled();
    });

    it('returns an empty entities block when skipLlm=true', async () => {
        const r = await ingestReportText({ text: 'hello 1.2.3.4', skipLlm: true });
        expect(r.entities).toEqual({});
        expect(r.llmError).toBeUndefined();
        expect(r.llmMeta).toBeUndefined();
    });
});

describe('ingestReportText — LLM enrichment', () => {
    afterEach(() => vi.clearAllMocks());

    it('returns LLM-extracted entities when the call succeeds', async () => {
        vi.mocked(helpers.extractEntities).mockResolvedValueOnce({
            threatActors: ['APT99'],
            malwareFamilies: ['EvilLoader'],
            campaigns: [],
            vulnerabilities: ['CVE-2024-12345'],
            techniques: ['T1059'],
            targetSectors: ['finance'],
            countries: [],
        });
        const r = await ingestReportText({ text: SAMPLE_REPORT });
        expect(r.entities.threatActors).toEqual(['APT99']);
        expect(r.entities.malwareFamilies).toEqual(['EvilLoader']);
        expect(r.llmError).toBeUndefined();
        expect(r.llmMeta?.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it('honours an explicit provider override', async () => {
        vi.mocked(helpers.extractEntities).mockResolvedValueOnce({});
        await ingestReportText({ text: SAMPLE_REPORT, provider: 'ollama' });
        expect(helpers.extractEntities).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({ provider: 'ollama' }),
        );
    });
});

describe('ingestReportText — graceful LLM degradation', () => {
    afterEach(() => vi.clearAllMocks());

    it('keeps IOCs and reports llmError when the LLM call throws', async () => {
        vi.mocked(helpers.extractEntities).mockRejectedValueOnce(new Error('upstream 429 rate limit'));
        const r = await ingestReportText({ text: SAMPLE_REPORT });
        expect(r.iocs.grouped.total).toBeGreaterThan(0);
        expect(r.entities).toEqual({});
        expect(r.llmError).toMatch(/rate limit/);
        expect(r.llmMeta).toBeUndefined();
    });
});

describe('ingestReportText — input handling', () => {
    afterEach(() => vi.clearAllMocks());

    it('truncates text past the MAX_TEXT_LEN cap', async () => {
        const huge = '1.2.3.4 '.repeat(50_000); // ~400 KB
        const r = await ingestReportText({ text: huge, skipLlm: true });
        expect(r.textLength).toBeLessThanOrEqual(200_000);
    });

    it('round-trips the source attribution', async () => {
        const r = await ingestReportText({
            text: 'IOC 1.1.1.1',
            source: 'Mandiant_2026_APT99.pdf',
            skipLlm: true,
        });
        expect(r.source).toBe('Mandiant_2026_APT99.pdf');
    });

    it('produces an ISO timestamp for extractedAt', async () => {
        const r = await ingestReportText({ text: 'x', skipLlm: true });
        expect(r.extractedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
});
