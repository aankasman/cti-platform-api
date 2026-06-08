/**
 * CEF / LEEF / ECS codec tests — locks the wire format so vendor
 * parsers don't break on future edits.
 */
import { describe, it, expect } from 'vitest';
import {
    toCef, toLeef, toEcs, toCefBatch, toLeefBatch, ecsToNdjson,
    type SiemIOC,
} from '@rinjani/core/siemFormatters';

const ipIoc: SiemIOC = {
    id: 'abc-123',
    type: 'ip',
    value: '1.2.3.4',
    threatType: 'c2',
    severity: 'critical',
    confidence: 92,
    source: 'threatfox',
    tags: ['ransomware', 'apt28'],
    firstSeen: '2026-06-01T00:00:00.000Z',
    lastSeen: '2026-06-08T12:00:00.000Z',
};

const urlIoc: SiemIOC = {
    id: 'url-1',
    type: 'url',
    value: 'http://evil.test/login.php?token=abc',
    threatType: 'phishing',
    severity: 'high',
    confidence: 80,
    source: 'urlhaus',
    lastSeen: '2026-06-08T00:00:00.000Z',
};

const sha256Ioc: SiemIOC = {
    id: 'h1',
    type: 'sha256',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    severity: 'medium',
    source: 'misp',
};

describe('toCef', () => {
    it('emits the seven-pipe header', () => {
        const out = toCef(ipIoc);
        // CEF:0 + vendor + product + version + sig + name + severity + ext = 8 parts → 7 pipes in body
        expect(out.startsWith('CEF:0|RinjaniAnalytics|CTI|1.0|c2|IOC observed: ip|10|')).toBe(true);
    });

    it('uses the right field token for IP', () => {
        expect(toCef(ipIoc)).toContain('dst=1.2.3.4');
    });

    it('uses request= for URL', () => {
        expect(toCef(urlIoc)).toContain('request=http://evil.test/login.php?token\\=abc');
    });

    it('uses fileHash= for sha256', () => {
        expect(toCef(sha256Ioc)).toContain('fileHash=e3b0c4');
    });

    it('escapes = signs in extensions', () => {
        expect(toCef(urlIoc)).toContain('token\\=abc');
    });

    it('normalises threatType to a header-safe signature (pipes stripped)', () => {
        // threatType feeds the CEF "sig" header position, which forbids pipes.
        // We pre-kebab the value, so a pipe never reaches the header.
        const evil: SiemIOC = { ...ipIoc, threatType: 'evil|injection' };
        const out = toCef(evil);
        const sig = out.split('|')[4];
        expect(sig).toBe('evil-injection');
    });

    it('does NOT escape pipes in extension values (per CEF spec)', () => {
        // Per CEF §3.3.2, extension values may contain pipes verbatim — only
        // `=`, `\`, and `\n` need escaping.
        const out = toCef({ ...ipIoc, threatType: 'evil|injection' });
        expect(out).toContain('cat=evil|injection');
    });

    it('maps severity to the CEF 0-10 scale', () => {
        expect(toCef({ ...ipIoc, severity: 'critical' })).toContain('|10|');
        expect(toCef({ ...ipIoc, severity: 'high' })).toContain('|8|');
        expect(toCef({ ...ipIoc, severity: 'medium' })).toContain('|5|');
        expect(toCef({ ...ipIoc, severity: 'low' })).toContain('|3|');
    });

    it('includes confidence as cn1', () => {
        expect(toCef(ipIoc)).toContain('cn1=92');
        expect(toCef(ipIoc)).toContain('cn1Label=confidence');
    });
});

describe('toLeef', () => {
    it('emits LEEF:2.0 header with vendor/product', () => {
        const out = toLeef(ipIoc);
        expect(out.startsWith('LEEF:2.0|RinjaniAnalytics|CTI|1.0|c2|x09|')).toBe(true);
    });

    it('separates extensions with a tab', () => {
        const out = toLeef(ipIoc);
        // The 7th `|` separator ends the header; the rest is tab-delimited
        const extPart = out.split('|').slice(6).join('|');
        expect(extPart).toContain('\t');
    });

    it('includes devTime as ISO string', () => {
        expect(toLeef(ipIoc)).toContain('devTime=2026-06-08T12:00:00.000Z');
    });

    it('strips newlines from extension values', () => {
        const evil: SiemIOC = { ...ipIoc, threatType: 'line1\nline2' };
        expect(toLeef(evil)).not.toContain('\n');
    });
});

describe('toEcs', () => {
    it('puts an IP under threat.indicator.ip', () => {
        const doc = toEcs(ipIoc);
        expect(doc.threat.indicator).toMatchObject({ ip: '1.2.3.4', type: 'ip', confidence: 92 });
    });

    it('puts a URL under threat.indicator.url.full', () => {
        const doc = toEcs(urlIoc);
        expect(doc.threat.indicator).toMatchObject({ url: { full: 'http://evil.test/login.php?token=abc' } });
    });

    it('puts SHA-256 under file.hash.sha256', () => {
        const doc = toEcs(sha256Ioc);
        expect((doc.threat.indicator as { file: { hash: { sha256: string } } }).file.hash.sha256)
            .toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('emits event.category=[threat] and event.type=[indicator]', () => {
        const doc = toEcs(ipIoc);
        expect(doc.event.category).toEqual(['threat']);
        expect(doc.event.type).toEqual(['indicator']);
    });

    it('preserves tags', () => {
        expect(toEcs(ipIoc).tags).toEqual(['ransomware', 'apt28']);
    });

    it('keeps the original id under rinjani.id', () => {
        expect(toEcs(ipIoc).rinjani.id).toBe('abc-123');
    });
});

describe('batch helpers', () => {
    it('toCefBatch joins with newlines and ends with newline', () => {
        const out = toCefBatch([ipIoc, urlIoc]);
        expect(out.split('\n').filter(Boolean)).toHaveLength(2);
        expect(out.endsWith('\n')).toBe(true);
    });

    it('toCefBatch on empty array yields empty string (no trailing newline)', () => {
        expect(toCefBatch([])).toBe('');
    });

    it('toLeefBatch joins with newlines', () => {
        const out = toLeefBatch([ipIoc, urlIoc]);
        expect(out.split('\n').filter(Boolean)).toHaveLength(2);
    });

    it('ecsToNdjson emits one JSON object per line', () => {
        const docs = [toEcs(ipIoc), toEcs(urlIoc)];
        const out = ecsToNdjson(docs);
        const lines = out.split('\n').filter(Boolean);
        expect(lines).toHaveLength(2);
        for (const line of lines) {
            const parsed = JSON.parse(line);
            expect(parsed.event.category).toEqual(['threat']);
        }
    });

    it('ecsToNdjson on empty array yields empty string', () => {
        expect(ecsToNdjson([])).toBe('');
    });
});
