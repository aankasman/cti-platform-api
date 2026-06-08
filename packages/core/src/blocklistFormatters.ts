/**
 * Vendor-neutral blocklist formatters for firewall External Dynamic List
 * (EDL) consumption. Phase 4 #4.
 *
 * Output formats:
 *   - Fortinet External Block List (text, one entry per line)
 *   - Palo Alto Networks EDL       (text, one entry per line; single-type lists)
 *   - Cisco Talos / ASA threat feed (text, one entry per line)
 *
 * All three share the same wire shape — line-delimited text. The
 * difference is per-vendor metadata + which entry types are admissible
 * in a single list. The functions below produce slightly-different
 * header comments and apply slightly-different validation rules so the
 * downstream box accepts the file.
 */

export type BlocklistEntryType = 'ip' | 'domain' | 'url';

export interface BlocklistIOC {
    type: string;        // ip | domain | url | hash | email
    value: string;
    severity?: string | null;
    source?: string | null;
}

/** True iff this IOC's value is plausibly admissible for the requested format slot. */
function admissible(ioc: BlocklistIOC, want: BlocklistEntryType): boolean {
    const t = ioc.type.toLowerCase();
    if (want === 'ip') return t === 'ip' || t === 'ipv4' || t === 'ipv6';
    if (want === 'domain') return t === 'domain' || t === 'hostname';
    if (want === 'url') return t === 'url';
    return false;
}

/** Reject obviously-bogus payloads before letting them into a firewall feed. */
function valid(ioc: BlocklistIOC, want: BlocklistEntryType): boolean {
    const v = ioc.value.trim();
    if (!v || v.length > 2048) return false;
    if (/[\r\n\t]/.test(v)) return false; // would break line-delimited parsers
    if (want === 'ip') return /^[0-9a-fA-F:.\/]+$/.test(v);
    if (want === 'domain') return /^[a-zA-Z0-9.\-_*]+$/.test(v) && v.includes('.');
    if (want === 'url') return /^https?:\/\//i.test(v);
    return true;
}

function header(generator: string, kind: BlocklistEntryType, count: number, sourceTag: string): string {
    return [
        `# ${generator}`,
        `# Format: ${kind} blocklist`,
        `# Entries: ${count}`,
        `# Source tag: ${sourceTag}`,
        // ISO timestamp omitted on purpose — caller adds it so the file
        // can be deterministic when sourced from a fixed cache key.
    ].join('\n');
}

// ============================================================================
// Fortinet External Block List
//   FortiGate `Security Profiles → External Block List` consumes a plain-text
//   feed of entries, one per line. IP, URL, or domain lists are configured
//   per-feed and must be homogeneous.
// ============================================================================

export function toFortinetFeed(iocs: BlocklistIOC[], kind: BlocklistEntryType): string {
    const entries = iocs.filter(i => admissible(i, kind) && valid(i, kind));
    const lines = entries.map(i => i.value.trim());
    return `${header('FortiGate External Block List', kind, lines.length, 'rinjani-analytics')}\n${lines.join('\n')}\n`;
}

// ============================================================================
// Palo Alto Networks EDL
//   PAN-OS `Objects → External Dynamic Lists` consumes:
//     - IP list      → IPv4 / IPv6, optional CIDR
//     - URL list     → matches HTTP/HTTPS URLs; wildcards (*) allowed
//     - Domain list  → exact host or subdomain match
//   Single-type per EDL. Comments start with `#`.
// ============================================================================

export function toPaloAltoEdl(iocs: BlocklistIOC[], kind: BlocklistEntryType): string {
    const entries = iocs.filter(i => admissible(i, kind) && valid(i, kind));
    const lines = entries.map(i => i.value.trim());
    return `${header('Palo Alto External Dynamic List', kind, lines.length, 'rinjani-analytics')}\n${lines.join('\n')}\n`;
}

// ============================================================================
// Cisco ASA / Firepower / Talos-compatible feed
//   Same wire format (line-delimited) but with a Cisco-style preamble.
// ============================================================================

export function toCiscoFeed(iocs: BlocklistIOC[], kind: BlocklistEntryType): string {
    const entries = iocs.filter(i => admissible(i, kind) && valid(i, kind));
    const lines = entries.map(i => i.value.trim());
    return `${header('Cisco Firewall Threat Feed', kind, lines.length, 'rinjani-analytics')}\n${lines.join('\n')}\n`;
}

// ============================================================================
// HMAC helper
//   Stable subscribable feeds need integrity. We attach an HMAC-SHA-256
//   signature header so downstream boxes can verify the body wasn't
//   tampered with in transit (separate from TLS, which only protects the
//   transport hop).
// ============================================================================

export async function hmacSign(body: string, secret: string): Promise<string> {
    const { createHmac } = await import('node:crypto');
    return createHmac('sha256', secret).update(body, 'utf8').digest('hex');
}
