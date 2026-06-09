/**
 * IOC regex extractor tests — Phase 3 #1.
 *
 * The extractor is pure and deterministic; these tests pin down the
 * decisions the algorithm makes (case normalisation, defang refanging,
 * dedup, file-extension filter, dedup by (kind, value)).
 */
import { describe, it, expect } from 'vitest';
import { extractIocs, refang, groupExtracted } from '@rinjani/core/iocExtractor';

describe('refang', () => {
    it('reverses common defang conventions', () => {
        expect(refang('evil[.]example[.]com')).toBe('evil.example.com');
        expect(refang('hxxp://evil.test')).toBe('http://evil.test');
        expect(refang('hxxps://evil.test')).toBe('https://evil.test');
        expect(refang('user[@]evil.test')).toBe('user@evil.test');
        expect(refang('10[.]0[.]0[.]1')).toBe('10.0.0.1');
        expect(refang('https[:]//example.com')).toBe('https://example.com');
    });

    it('leaves non-defanged text untouched', () => {
        expect(refang('evil.com')).toBe('evil.com');
        expect(refang('http://x.test')).toBe('http://x.test');
    });
});

describe('extractIocs — IPs', () => {
    it('extracts IPv4 addresses', () => {
        const r = extractIocs('Beacon to 192.168.1.10 and 8.8.8.8');
        expect(r.map(i => `${i.kind}:${i.value}`)).toEqual([
            'ipv4:192.168.1.10',
            'ipv4:8.8.8.8',
        ]);
    });

    it('rejects malformed IPv4 (octets > 255)', () => {
        const r = extractIocs('999.999.999.999 not an IP');
        expect(r.filter(i => i.kind === 'ipv4')).toHaveLength(0);
    });

    it('extracts a basic IPv6 address', () => {
        const r = extractIocs('Logged from 2001:db8::1 last night');
        expect(r.some(i => i.kind === 'ipv6' && i.value === '2001:db8::1')).toBe(true);
    });
});

describe('extractIocs — URLs + domains', () => {
    it('extracts URLs', () => {
        const r = extractIocs('Phishing page at https://evil.example.com/login?id=1');
        const urls = r.filter(i => i.kind === 'url');
        expect(urls).toHaveLength(1);
        expect(urls[0].value).toBe('https://evil.example.com/login?id=1');
    });

    it('also surfaces the host as a domain when a URL is present', () => {
        const r = extractIocs('Phishing at https://evil.example.com/x');
        expect(r.some(i => i.kind === 'domain' && i.value === 'evil.example.com')).toBe(true);
    });

    it('refangs defanged URLs before matching', () => {
        const r = extractIocs('Avoid hxxps://evil[.]test/x');
        expect(r.some(i => i.kind === 'url' && i.value === 'https://evil.test/x')).toBe(true);
        expect(r.some(i => i.kind === 'domain' && i.value === 'evil.test')).toBe(true);
    });

    it('rejects file extensions that look like domains by default', () => {
        const r = extractIocs('See report.pdf for details');
        expect(r.filter(i => i.kind === 'domain')).toHaveLength(0);
    });

    it('lowercases domains for consistent dedup', () => {
        const r = extractIocs('Evil.COM and evil.com same actor');
        const domains = r.filter(i => i.kind === 'domain');
        expect(domains).toHaveLength(1);
        expect(domains[0].value).toBe('evil.com');
    });
});

describe('extractIocs — hashes', () => {
    it('classifies MD5 (32 hex)', () => {
        const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
        const r = extractIocs(`Sample md5: ${md5}`);
        expect(r.find(i => i.kind === 'hash-md5')?.value).toBe(md5);
    });

    it('classifies SHA-1 (40 hex)', () => {
        const sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
        const r = extractIocs(`sha1=${sha1}`);
        expect(r.find(i => i.kind === 'hash-sha1')?.value).toBe(sha1);
    });

    it('classifies SHA-256 (64 hex)', () => {
        const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        const r = extractIocs(`SHA256: ${sha256.toUpperCase()}`);
        const hit = r.find(i => i.kind === 'hash-sha256');
        expect(hit?.value).toBe(sha256); // lowercased
    });

    it('does not classify a 64-hex SHA-256 as MD5+SHA1 too', () => {
        const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        const r = extractIocs(sha256);
        // Should ONLY be the sha256 hit
        const hashes = r.filter(i => i.kind.startsWith('hash'));
        expect(hashes).toHaveLength(1);
        expect(hashes[0].kind).toBe('hash-sha256');
    });
});

describe('extractIocs — emails + CVEs', () => {
    it('extracts emails (lowercased)', () => {
        const r = extractIocs('Contact Phisher@EVIL.test for ransom');
        expect(r.find(i => i.kind === 'email')?.value).toBe('phisher@evil.test');
    });

    it('extracts CVE IDs (uppercased)', () => {
        const r = extractIocs('Exploits cve-2024-1234 and CVE-2026-99999');
        const cves = r.filter(i => i.kind === 'cve').map(i => i.value);
        expect(cves).toEqual(['CVE-2024-1234', 'CVE-2026-99999']);
    });
});

describe('extractIocs — dedup + ordering', () => {
    it('returns items sorted by first-occurrence offset', () => {
        const r = extractIocs('cve-2024-9999 then 1.1.1.1 then evil.test then CVE-2024-9999 again');
        // Each item appears once (dedup); order = first-occurrence
        const values = r.map(i => i.value);
        expect(values.indexOf('CVE-2024-9999')).toBeLessThan(values.indexOf('1.1.1.1'));
        expect(values.indexOf('1.1.1.1')).toBeLessThan(values.indexOf('evil.test'));
    });

    it('dedups (kind, value) pairs', () => {
        const r = extractIocs('evil.com and evil.com again and again');
        expect(r.filter(i => i.kind === 'domain' && i.value === 'evil.com')).toHaveLength(1);
    });
});

describe('groupExtracted', () => {
    it('produces a grouped summary suitable for UI rendering', () => {
        const text = 'IP 1.2.3.4 hits https://evil.test from user@evil.test, CVE-2024-1234';
        const g = groupExtracted(extractIocs(text));
        expect(g.ipv4).toEqual(['1.2.3.4']);
        expect(g.url).toEqual(['https://evil.test']);
        expect(g.domain).toEqual(['evil.test']);
        expect(g.email).toEqual(['user@evil.test']);
        expect(g.cve).toEqual(['CVE-2024-1234']);
        expect(g.total).toBeGreaterThanOrEqual(5);
    });

    it('returns empty groups for empty input', () => {
        const g = groupExtracted([]);
        expect(g.total).toBe(0);
        expect(g.ipv4).toEqual([]);
    });
});
