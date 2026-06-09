/**
 * Pure-regex IOC extractor for free-form report text.
 *
 * Phase 3 #1 (Report ingestion). The LLM-based entity extractor in
 * `apps/api/src/services/aiMiddleware/helpers.ts` handles fuzzy entities
 * (threat-actor names, malware families, campaigns, sectors). This file
 * handles the deterministic part — values that have a recognisable shape:
 *
 *   - IPv4 / IPv6
 *   - domains + URLs
 *   - file hashes (MD5, SHA-1, SHA-256)
 *   - email addresses
 *   - CVE IDs
 *
 * Pure functions only — no I/O, no DB, no LLM. Same composability as
 * the SIEM formatters and STIX vocab modules in this package.
 *
 * Defanging: reports routinely render `evil[.]com` or `hxxp://...`
 * so links don't auto-resolve in PDFs/Slack. We refang before matching
 * so the operator's input shape doesn't matter.
 */

export type IocKind = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash-md5' | 'hash-sha1' | 'hash-sha256' | 'email' | 'cve';

export interface ExtractedIoc {
    kind: IocKind;
    value: string;
    /** Character offset in the (refanged) input — useful for highlight rendering downstream. */
    offset: number;
}

// ============================================================================
// Defanging
// ============================================================================

/**
 * Reverse common defanging conventions so the matchers see canonical values.
 * Conservative — only well-known patterns:
 *   `hxxp://` → `http://`, `hxxps://` → `https://`
 *   `[.]`, `(.)`, `{.}` → `.`
 *   `[@]`, `(@)` → `@`
 *   `[:]` → `:`
 */
export function refang(input: string): string {
    return input
        .replace(/\bhxxps:\/\//gi, 'https://')
        .replace(/\bhxxp:\/\//gi, 'http://')
        .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
        .replace(/\[@\]|\(@\)/g, '@')
        .replace(/\[:\]/g, ':');
}

// ============================================================================
// Patterns
// ============================================================================

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;

// Conservative IPv6: requires at least one `::` or 7 colons. Avoids false positives on time stamps.
const IPV6 = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4})?\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g;

const URL = /\bhttps?:\/\/[^\s<>"')]+/gi;

// Domains: at least one dot, TLD ≥ 2 chars, no underscores. Excludes pure numeric (caught by IPV4).
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

const HASH_MD5 = /\b[a-fA-F0-9]{32}\b/g;
const HASH_SHA1 = /\b[a-fA-F0-9]{40}\b/g;
const HASH_SHA256 = /\b[a-fA-F0-9]{64}\b/g;

const EMAIL = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi;

const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;

// Common TLDs we treat as low-risk noise when a "domain" hit is a sentence ending
// like "in." or "a.m." — keep this conservative.
const KNOWN_TLDS_MIN_LEN = 2;

// File extensions that look like domains but aren't (e.g. "report.pdf").
const FILE_EXT_DENYLIST = new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'log',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'mp3', 'mp4', 'avi',
    'zip', 'rar', 'tar', 'gz', '7z',
    'exe', 'dll', 'so', 'bin', 'msi', 'app', 'dmg',
    'json', 'xml', 'yml', 'yaml', 'toml', 'csv', 'md',
]);

// ============================================================================
// Extractor
// ============================================================================

interface ExtractOptions {
    /**
     * If true, returned values keep their original casing. If false (default),
     * domains + emails are lowercased so deduplication works across `Evil.COM`
     * and `evil.com`. Hashes are always lowercased.
     */
    preserveCase?: boolean;
    /**
     * Reject domains where the right-most label is in the file-extension
     * denylist. Defaults to true — `report.pdf` is almost never an IOC.
     */
    filterFileExtensions?: boolean;
}

/**
 * Extract IOCs from free-form text. Returns a deduplicated list keyed by
 * `(kind, value)` — same value can appear as both `domain` and the host
 * part of a `url`; both are reported once each.
 *
 * The order in the output matches first-occurrence in the (refanged) input.
 */
export function extractIocs(input: string, opts: ExtractOptions = {}): ExtractedIoc[] {
    const filterFileExt = opts.filterFileExtensions ?? true;
    const text = refang(input);

    const out: ExtractedIoc[] = [];
    const seen = new Set<string>();

    const pushUnique = (kind: IocKind, raw: string, offset: number) => {
        const value = normaliseForKind(kind, raw, opts.preserveCase ?? false);
        const key = `${kind}|${value}`;
        if (seen.has(key)) return;
        seen.add(key);
        out.push({ kind, value, offset });
    };

    // Order matters — match hashes before domains (a 64-hex string would match
    // neither, but a 32-hex MD5 could partially match a domain's first label).
    // Match URLs before domains so the URL takes the slot but the host also
    // surfaces as a domain.
    for (const m of text.matchAll(HASH_SHA256)) pushUnique('hash-sha256', m[0], m.index ?? 0);
    for (const m of text.matchAll(HASH_SHA1)) pushUnique('hash-sha1', m[0], m.index ?? 0);
    for (const m of text.matchAll(HASH_MD5)) pushUnique('hash-md5', m[0], m.index ?? 0);
    for (const m of text.matchAll(IPV6)) pushUnique('ipv6', m[0], m.index ?? 0);
    for (const m of text.matchAll(IPV4)) pushUnique('ipv4', m[0], m.index ?? 0);
    for (const m of text.matchAll(URL)) pushUnique('url', m[0], m.index ?? 0);
    for (const m of text.matchAll(EMAIL)) pushUnique('email', m[0], m.index ?? 0);
    for (const m of text.matchAll(CVE)) pushUnique('cve', m[0], m.index ?? 0);

    for (const m of text.matchAll(DOMAIN)) {
        const raw = m[0];
        if (filterFileExt) {
            const tld = raw.split('.').pop()?.toLowerCase() ?? '';
            if (FILE_EXT_DENYLIST.has(tld)) continue;
            if (tld.length < KNOWN_TLDS_MIN_LEN) continue;
        }
        // Skip if this domain is purely the host part of an already-captured URL —
        // we still report it once but only if it appears outside the URL context too.
        // Simpler: always emit; downstream dedup uses (kind, value).
        pushUnique('domain', raw, m.index ?? 0);
    }

    return out.sort((a, b) => a.offset - b.offset);
}

function normaliseForKind(kind: IocKind, raw: string, preserveCase: boolean): string {
    switch (kind) {
        case 'hash-md5':
        case 'hash-sha1':
        case 'hash-sha256':
            return raw.toLowerCase();
        case 'domain':
        case 'email':
        case 'url':
            return preserveCase ? raw : raw.toLowerCase();
        case 'cve':
            return raw.toUpperCase();
        default:
            return raw;
    }
}

// ============================================================================
// Convenience — grouped output for review surfaces
// ============================================================================

export interface GroupedIocs {
    ipv4: string[];
    ipv6: string[];
    domain: string[];
    url: string[];
    'hash-md5': string[];
    'hash-sha1': string[];
    'hash-sha256': string[];
    email: string[];
    cve: string[];
    /** Total count across all groups. */
    total: number;
}

export function groupExtracted(iocs: ExtractedIoc[]): GroupedIocs {
    const g: GroupedIocs = {
        ipv4: [], ipv6: [], domain: [], url: [],
        'hash-md5': [], 'hash-sha1': [], 'hash-sha256': [],
        email: [], cve: [],
        total: 0,
    };
    for (const i of iocs) {
        g[i.kind].push(i.value);
        g.total++;
    }
    return g;
}
