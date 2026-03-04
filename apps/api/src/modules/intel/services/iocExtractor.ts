/**
 * IOC Extractor Service
 *
 * Extracts Indicators of Compromise from unstructured text using
 * comprehensive regex patterns. Supports:
 *   - IPv4, IPv6
 *   - Domains, URLs
 *   - Hashes (MD5, SHA1, SHA256)
 *   - Email addresses
 *   - CVE IDs
 *   - MITRE ATT&CK IDs (Txxxx, Txxxx.xxx)
 *
 * Also handles defanging/refanging of IOCs.
 */

import crypto from 'crypto';

// ============================================================================
// Types
// ============================================================================

export type IOCType =
    | 'ipv4'
    | 'ipv6'
    | 'domain'
    | 'url'
    | 'hash-md5'
    | 'hash-sha1'
    | 'hash-sha256'
    | 'email'
    | 'cve'
    | 'mitre-technique';

export interface ExtractedIOC {
    type: IOCType;
    value: string;            // refanged, normalized value
    rawValue: string;         // original value from text
    confidence: number;       // 0-100
    context?: string;         // surrounding text snippet
    canonicalId: string;      // SHA-256 of type:normalizedValue
}

export interface ExtractionResult {
    iocs: ExtractedIOC[];
    stats: {
        total: number;
        byType: Record<string, number>;
        duplicatesRemoved: number;
    };
}

// ============================================================================
// Regex Patterns
// ============================================================================

// IPv4: standard dotted quad (with optional defanged brackets)
const IPV4_RE = /(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\[?\.\]?)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\[?\.\]?)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\[?\.\]?)(?:25[0-5]|2[0-4]\d|[01]?\d\d?))/g;

// IPv6: simplified, catches most common formats
const IPV6_RE = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}/g;

// Domain: multi-label with defang support
const DOMAIN_RE = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[?\.\]?))+[a-zA-Z]{2,}/g;

// URL: http/https with defang support (hxxp, hxxps, [.], etc.)
const URL_RE = /(?:h[tx]{2}ps?:\/\/|https?:\/\/)[\w\-._~:/?#[\]@!$&'()*+,;=%]+/gi;

// Hash patterns
const MD5_RE = /\b([a-fA-F0-9]{32})\b/g;
const SHA1_RE = /\b([a-fA-F0-9]{40})\b/g;
const SHA256_RE = /\b([a-fA-F0-9]{64})\b/g;

// Email
const EMAIL_RE = /[a-zA-Z0-9._%+\-]+(?:@|\[@\]|\[at\])(?:[a-zA-Z0-9.\-]+(?:\[?\.\]?)[a-zA-Z]{2,})/gi;

// CVE IDs
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

// MITRE ATT&CK technique IDs
const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

// ============================================================================
// Defang / Refang
// ============================================================================

/**
 * Refang a potentially defanged IOC value back to its original form.
 */
export function refang(value: string): string {
    return value
        .replace(/\[\.\]/g, '.')      // [.] → .
        .replace(/\[dot\]/gi, '.')    // [dot] → .
        .replace(/hxxp/gi, 'http')   // hxxp → http
        .replace(/\[:\]/g, ':')      // [:] → :
        .replace(/\[@\]/g, '@')      // [@] → @
        .replace(/\[at\]/gi, '@')    // [at] → @
        .replace(/\\\./g, '.');       // \. → .
}

/**
 * Defang an IOC value for safe display.
 */
export function defang(value: string): string {
    return value
        .replace(/\./g, '[.]')
        .replace(/http/gi, 'hxxp')
        .replace(/@/g, '[@]');
}

// ============================================================================
// Canonical ID Generation
// ============================================================================

/**
 * Generate a deterministic canonical ID for an IOC.
 * Uses SHA-256 of `type:normalizedValue`.
 */
function canonicalId(type: IOCType, value: string): string {
    const normalized = value.toLowerCase().trim();
    return crypto.createHash('sha256').update(`${type}:${normalized}`).digest('hex');
}

// ============================================================================
// Context Extraction
// ============================================================================

function getContext(text: string, match: string, windowSize: number = 80): string {
    const idx = text.indexOf(match);
    if (idx === -1) return '';
    const start = Math.max(0, idx - windowSize);
    const end = Math.min(text.length, idx + match.length + windowSize);
    return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

// ============================================================================
// Validation Helpers
// ============================================================================

// Common false-positive domains to ignore
const IGNORE_DOMAINS = new Set([
    'example.com', 'localhost', 'test.com', 'foo.bar',
    'schema.org', 'w3.org', 'xmlns.com', 'purl.org',
    'github.com', 'googleapis.com', 'google.com', 'twitter.com',
]);

// Common words that look like hashes but aren't
const MIN_HEX_ENTROPY = 3.0; // bits per character

function hexEntropy(hex: string): number {
    const freq: Record<string, number> = {};
    for (const c of hex.toLowerCase()) {
        freq[c] = (freq[c] || 0) + 1;
    }
    let entropy = 0;
    const len = hex.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function isValidIPv4(ip: string): boolean {
    const parts = refang(ip).split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
        const n = parseInt(p, 10);
        return !isNaN(n) && n >= 0 && n <= 255;
    });
}

function isPrivateIP(ip: string): boolean {
    const parts = refang(ip).split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    return false;
}

function isValidDomain(domain: string): boolean {
    const clean = refang(domain).toLowerCase();
    if (clean.length < 4) return false;
    if (!clean.includes('.')) return false;
    if (IGNORE_DOMAINS.has(clean)) return false;
    // Must have a valid TLD (2-20 chars)
    const tld = clean.split('.').pop() || '';
    if (tld.length < 2 || tld.length > 20) return false;
    // Don't match version numbers like "1.2.3"
    if (/^\d+\.\d+(\.\d+)+$/.test(clean)) return false;
    return true;
}

// ============================================================================
// Main Extraction Function
// ============================================================================

/**
 * Extract all IOCs from unstructured text.
 * Returns deduplicated, validated IOCs with confidence scores and context.
 */
export function extractIOCs(text: string): ExtractionResult {
    const iocs: ExtractedIOC[] = [];
    const seen = new Set<string>(); // canonical IDs for dedup
    let duplicatesRemoved = 0;

    function addIOC(type: IOCType, rawValue: string, confidence: number) {
        const value = refang(rawValue).trim();
        const id = canonicalId(type, value);
        if (seen.has(id)) {
            duplicatesRemoved++;
            return;
        }
        seen.add(id);
        iocs.push({
            type,
            value,
            rawValue,
            confidence,
            context: getContext(text, rawValue),
            canonicalId: id,
        });
    }

    // Order matters: extract URLs before domains to avoid false domain matches

    // 1. URLs
    for (const m of text.matchAll(URL_RE)) {
        addIOC('url', m[0], 85);
    }

    // 2. CVE IDs
    for (const m of text.matchAll(CVE_RE)) {
        addIOC('cve', m[0].toUpperCase(), 95);
    }

    // 3. MITRE ATT&CK IDs
    for (const m of text.matchAll(MITRE_RE)) {
        addIOC('mitre-technique', m[0], 90);
    }

    // 4. Emails
    for (const m of text.matchAll(EMAIL_RE)) {
        addIOC('email', m[0], 70);
    }

    // 5. SHA-256 (check before SHA-1 and MD5 due to length)
    for (const m of text.matchAll(SHA256_RE)) {
        if (hexEntropy(m[1]) >= MIN_HEX_ENTROPY) {
            addIOC('hash-sha256', m[1], 90);
        }
    }

    // 6. SHA-1
    for (const m of text.matchAll(SHA1_RE)) {
        if (hexEntropy(m[1]) >= MIN_HEX_ENTROPY) {
            addIOC('hash-sha1', m[1], 85);
        }
    }

    // 7. MD5
    for (const m of text.matchAll(MD5_RE)) {
        if (hexEntropy(m[1]) >= MIN_HEX_ENTROPY) {
            addIOC('hash-md5', m[1], 80);
        }
    }

    // 8. IPv4
    for (const m of text.matchAll(IPV4_RE)) {
        const ip = refang(m[0]);
        if (isValidIPv4(ip) && !isPrivateIP(ip)) {
            addIOC('ipv4', m[0], 85);
        }
    }

    // 9. IPv6
    for (const m of text.matchAll(IPV6_RE)) {
        addIOC('ipv6', m[0], 80);
    }

    // 10. Domains (extract last to avoid overlapping with URLs)
    for (const m of text.matchAll(DOMAIN_RE)) {
        const domain = refang(m[0]).toLowerCase();
        if (isValidDomain(domain)) {
            // Skip if this domain is already captured as part of a URL
            const alreadyInUrl = iocs.some(
                ioc => ioc.type === 'url' && ioc.value.includes(domain),
            );
            if (!alreadyInUrl) {
                addIOC('domain', m[0], 75);
            }
        }
    }

    // Build stats
    const byType: Record<string, number> = {};
    for (const ioc of iocs) {
        byType[ioc.type] = (byType[ioc.type] || 0) + 1;
    }

    return {
        iocs,
        stats: {
            total: iocs.length,
            byType,
            duplicatesRemoved,
        },
    };
}

/**
 * Extract IOCs from multiple text blocks (e.g., title + description + content).
 * Deduplicates across all blocks.
 */
export function extractIOCsFromMultiple(texts: string[]): ExtractionResult {
    const combined = texts.filter(Boolean).join('\n\n');
    return extractIOCs(combined);
}
