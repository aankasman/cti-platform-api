/**
 * Blocklist firewall feed formatter tests — locks per-vendor wire
 * shape and the validation layer that protects the downstream box
 * from getting fed garbage.
 */
import { describe, it, expect } from 'vitest';
import {
    toFortinetFeed, toPaloAltoEdl, toCiscoFeed, hmacSign,
    type BlocklistIOC,
} from '@rinjani/core/blocklistFormatters';

const ips: BlocklistIOC[] = [
    { type: 'ip', value: '1.2.3.4', severity: 'critical', source: 'threatfox' },
    { type: 'ipv4', value: '5.6.7.0/24', severity: 'high', source: 'misp' },
    { type: 'ipv6', value: '2001:db8::/32', severity: 'medium', source: 'abuseipdb' },
];

const domains: BlocklistIOC[] = [
    { type: 'domain', value: 'evil.example.com', severity: 'critical', source: 'urlhaus' },
    { type: 'hostname', value: 'c2.bad.test', severity: 'high', source: 'threatfox' },
];

const urls: BlocklistIOC[] = [
    { type: 'url', value: 'http://evil.example.com/payload.exe', severity: 'high', source: 'urlhaus' },
    { type: 'url', value: 'https://phish.test/login.html', severity: 'critical', source: 'phishtank' },
];

// Bad inputs the validator should drop
const mixed: BlocklistIOC[] = [
    ...ips,
    { type: 'ip', value: '\nINJECTION', severity: 'high', source: 'bogus' },          // newline
    { type: 'ip', value: 'not-an-ip-at-all', severity: 'high', source: 'bogus' },     // alpha-only
    { type: 'domain', value: 'noTld', severity: 'high', source: 'bogus' },             // missing dot
    { type: 'url', value: 'ftp://wrong-scheme', severity: 'high', source: 'bogus' },   // not http(s)
    { type: 'email', value: 'attacker@bad.test', severity: 'high', source: 'bogus' },  // wrong type
];

describe('toFortinetFeed', () => {
    it('emits header + IPs only when kind=ip', () => {
        const out = toFortinetFeed(ips, 'ip');
        expect(out).toMatch(/^# FortiGate External Block List/);
        expect(out).toContain('# Entries: 3');
        expect(out).toContain('1.2.3.4');
        expect(out).toContain('5.6.7.0/24');
        expect(out).toContain('2001:db8::/32');
        expect(out).not.toContain('evil.example.com');
    });

    it('drops invalid + wrong-type entries', () => {
        const out = toFortinetFeed(mixed, 'ip');
        expect(out).toContain('# Entries: 3'); // only the 3 valid IPs survive
        expect(out).not.toContain('INJECTION');
        expect(out).not.toContain('not-an-ip-at-all');
        expect(out).not.toContain('attacker@bad.test');
    });

    it('emits domain feed when kind=domain', () => {
        const out = toFortinetFeed(domains, 'domain');
        expect(out).toContain('# Entries: 2');
        expect(out).toContain('evil.example.com');
        expect(out).toContain('c2.bad.test');
    });
});

describe('toPaloAltoEdl', () => {
    it('emits PAN header', () => {
        const out = toPaloAltoEdl(ips, 'ip');
        expect(out.startsWith('# Palo Alto External Dynamic List')).toBe(true);
    });

    it('emits URL list when kind=url', () => {
        const out = toPaloAltoEdl(urls, 'url');
        expect(out).toContain('# Entries: 2');
        expect(out).toContain('http://evil.example.com/payload.exe');
        expect(out).toContain('https://phish.test/login.html');
    });

    it('rejects ftp:// URLs', () => {
        const bad: BlocklistIOC[] = [{ type: 'url', value: 'ftp://wrong', source: null }];
        expect(toPaloAltoEdl(bad, 'url')).toContain('# Entries: 0');
    });
});

describe('toCiscoFeed', () => {
    it('emits Cisco header', () => {
        const out = toCiscoFeed(domains, 'domain');
        expect(out.startsWith('# Cisco Firewall Threat Feed')).toBe(true);
        expect(out).toContain('# Entries: 2');
    });

    it('returns header-only (Entries: 0) when no admissible IOCs', () => {
        const out = toCiscoFeed([], 'ip');
        expect(out).toContain('# Entries: 0');
    });
});

describe('hmacSign', () => {
    it('produces a stable hex digest', async () => {
        const sig = await hmacSign('hello', 'super-secret');
        // Known SHA-256 HMAC of "hello" with "super-secret"
        // (verified with: openssl dgst -sha256 -hmac super-secret <<< hello).
        expect(sig).toBe('7c99e208210b37e2243b9d9523a199b4bde735624f320516b0b7d1e2b22fb864');
    });

    it('changes when the body changes', async () => {
        const s1 = await hmacSign('a', 'secret');
        const s2 = await hmacSign('b', 'secret');
        expect(s1).not.toBe(s2);
    });

    it('changes when the secret changes', async () => {
        const s1 = await hmacSign('body', 'secret1');
        const s2 = await hmacSign('body', 'secret2');
        expect(s1).not.toBe(s2);
    });
});
