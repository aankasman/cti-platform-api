/**
 * SIEM direct-push tests — Phase 4 #2 closer.
 *
 * The over-the-wire fetch path needs a real Splunk HEC token / Elastic
 * cluster (covered in the PR test plan). These unit tests cover the
 * deterministic pieces: NDJSON shape, idempotent doc IDs, env-driven
 * fail-closed behaviour.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { toHecBody, pushToSplunk } from '../services/siemPush/splunkHec';
import { toBulkBody, pushToElastic } from '../services/siemPush/elasticBulk';
import type { SiemIOC } from '@rinjani/core/siemFormatters';

const SAMPLE: SiemIOC[] = [
    {
        id: 'ioc-1', type: 'ip', value: '1.2.3.4',
        severity: 'high', confidence: 80, source: 'otx',
        firstSeen: '2026-06-01T00:00:00Z', lastSeen: '2026-06-09T00:00:00Z',
    },
    {
        id: 'ioc-2', type: 'domain', value: 'evil.test',
        severity: 'critical', confidence: 95, source: 'urlhaus',
        firstSeen: '2026-06-02T00:00:00Z', lastSeen: '2026-06-08T12:00:00Z',
    },
];

const ENV_KEYS = [
    'SPLUNK_HEC_URL', 'SPLUNK_HEC_TOKEN', 'SPLUNK_HEC_INDEX', 'SPLUNK_HEC_SOURCETYPE',
    'ELASTIC_URL', 'ELASTIC_INDEX', 'ELASTIC_API_KEY', 'ELASTIC_USER', 'ELASTIC_PASSWORD',
];
let saved: Record<string, string | undefined>;
beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map(k => [k, process.env[k]]));
    for (const k of ENV_KEYS) delete process.env[k];
});
afterEach(() => {
    for (const k of ENV_KEYS) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
    }
});

// ── Splunk HEC body ────────────────────────────────────────────────

describe('toHecBody', () => {
    it('produces one HEC envelope per line, each wrapping an ECS event', () => {
        const body = toHecBody(SAMPLE, { index: 'rinjani_cti', sourcetype: 'rinjani:cti:ioc' });
        const lines = body.split('\n');
        expect(lines).toHaveLength(2);
        const first = JSON.parse(lines[0]);
        expect(first.sourcetype).toBe('rinjani:cti:ioc');
        expect(first.index).toBe('rinjani_cti');
        expect(first.event.threat.indicator.type).toBe('ip');
        expect(first.event.rinjani.id).toBe('ioc-1');
    });

    it('emits Splunk-friendly epoch-seconds time when the IOC has a timestamp', () => {
        const body = toHecBody(SAMPLE, { sourcetype: 'x' });
        const first = JSON.parse(body.split('\n')[0]);
        // 2026-06-09T00:00:00Z → 1780000000ish
        expect(typeof first.time).toBe('number');
        expect(first.time).toBeGreaterThan(1_500_000_000);
    });

    it('omits the time field when both seen timestamps are absent', () => {
        const body = toHecBody([{ id: 'a', type: 'ip', value: '8.8.8.8' }], { sourcetype: 's' });
        const first = JSON.parse(body);
        expect(first.time).toBeUndefined();
    });

    it('omits index when caller did not configure one', () => {
        const body = toHecBody(SAMPLE, { sourcetype: 's' });
        const first = JSON.parse(body.split('\n')[0]);
        expect(first.index).toBeUndefined();
    });
});

describe('pushToSplunk — fail-closed', () => {
    it('returns ok:false when SPLUNK_HEC_URL is missing', async () => {
        const r = await pushToSplunk(SAMPLE);
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/not configured/);
    });

    it('returns ok:false when token is missing despite URL set', async () => {
        process.env.SPLUNK_HEC_URL = 'https://splunk.example.com:8088';
        const r = await pushToSplunk(SAMPLE);
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/not configured/);
    });

    it('short-circuits ok with zero work on an empty batch', async () => {
        process.env.SPLUNK_HEC_URL = 'https://splunk.example.com:8088';
        process.env.SPLUNK_HEC_TOKEN = 'shh';
        const r = await pushToSplunk([]);
        expect(r.ok).toBe(true);
        expect(r.batchSize).toBe(0);
        expect(r.accepted).toBe(0);
    });
});

// ── Elastic _bulk body ─────────────────────────────────────────────

describe('toBulkBody', () => {
    it('produces NDJSON with action+doc pair per IOC and a trailing newline', () => {
        const body = toBulkBody(SAMPLE, 'rinjani-cti-iocs');
        expect(body.endsWith('\n')).toBe(true);
        const lines = body.split('\n').filter(Boolean);
        expect(lines).toHaveLength(4); // 2 IOCs * 2 lines each
        const meta = JSON.parse(lines[0]);
        const doc = JSON.parse(lines[1]);
        expect(meta.index._index).toBe('rinjani-cti-iocs');
        expect(meta.index._id).toBe('ioc-1');           // idempotent: doc id = IOC id
        expect(doc.threat.indicator.type).toBe('ip');
    });

    it('returns an empty string for empty input (no stray newline)', () => {
        const body = toBulkBody([], 'idx');
        expect(body).toBe('');
    });
});

describe('pushToElastic — fail-closed', () => {
    it('returns ok:false when ELASTIC_URL is missing', async () => {
        const r = await pushToElastic(SAMPLE);
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/ELASTIC_URL/);
    });

    it('returns ok:false when URL is set but no credentials configured', async () => {
        process.env.ELASTIC_URL = 'https://elastic.example.com:9200';
        const r = await pushToElastic(SAMPLE);
        expect(r.ok).toBe(false);
        expect(r.error).toMatch(/credentials required/);
    });

    it('accepts ELASTIC_USER + ELASTIC_PASSWORD as Basic auth fallback', async () => {
        process.env.ELASTIC_URL = 'https://elastic.example.com:9200';
        process.env.ELASTIC_USER = 'rinjani';
        process.env.ELASTIC_PASSWORD = 'pw';
        // No fetch mock — we expect the network call to fail with a non-"not configured" message.
        const r = await pushToElastic([SAMPLE[0]]);
        expect(r.ok).toBe(false);
        // Either a fetch error (resolution / TLS) or a HTTP error from the fake URL.
        // The point is: we *tried*, so it's not the 'not configured' path.
        expect(r.error).not.toMatch(/not configured/i);
        expect(r.error).not.toMatch(/credentials required/i);
    });

    it('short-circuits ok with zero work on an empty batch', async () => {
        process.env.ELASTIC_URL = 'https://elastic.example.com:9200';
        process.env.ELASTIC_API_KEY = 'k';
        const r = await pushToElastic([]);
        expect(r.ok).toBe(true);
        expect(r.batchSize).toBe(0);
        expect(r.indexed).toBe(0);
    });
});
