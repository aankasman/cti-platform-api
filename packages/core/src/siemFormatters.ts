/**
 * SIEM-friendly IOC formatters.
 *
 * Phase 4 #2. Pure converters from our internal IOC shape to three
 * vendor-neutral SIEM log formats. No I/O — callers query the DB and
 * pipe rows through these.
 *
 * Formats:
 *   - CEF (Common Event Format)    — used by ArcSight, Splunk, Sentinel, IBM QRadar
 *   - LEEF (Log Event Extended Format) — IBM QRadar native
 *   - ECS (Elastic Common Schema)  — Elastic / OpenSearch / Beats / Logstash
 *
 * Specs:
 *   CEF — https://docs.cybertronics.com/sec/CEF.pdf
 *   LEEF v2 — https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components
 *   ECS — https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
 */

export interface SiemIOC {
    id: string;
    type: string;             // ip | domain | url | hash | email
    value: string;
    threatType?: string | null;
    severity?: string | null;
    confidence?: number | null;
    source?: string | null;
    tags?: string[] | null;
    firstSeen?: string | Date | null;
    lastSeen?: string | Date | null;
}

const VENDOR = 'RinjaniAnalytics';
const PRODUCT = 'CTI';
const VERSION = '1.0';

const SEVERITY_TO_CEF: Record<string, number> = {
    critical: 10,
    high: 8,
    medium: 5,
    low: 3,
    informational: 1,
    info: 1,
};

const IOC_TYPE_TO_CEF_FIELD: Record<string, string> = {
    ip: 'dst',
    ipv4: 'dst',
    ipv6: 'dst',
    domain: 'destinationDnsDomain',
    hostname: 'destinationDnsDomain',
    url: 'request',
    hash: 'fileHash',
    'hash-md5': 'fileHash',
    'hash-sha1': 'fileHash',
    'hash-sha256': 'fileHash',
    md5: 'fileHash',
    sha1: 'fileHash',
    sha256: 'fileHash',
    email: 'suser',
};

// ============================================================================
// CEF — pipe-delimited header + key=value extensions
// ============================================================================

/** Escape per CEF spec §3.3.2 — backslash, pipe, equals in headers; backslash + equals + newline in extensions. */
function escapeCefHeader(s: string): string {
    return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}
function escapeCefExt(s: string): string {
    return s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, '\\n');
}

function isoOrNow(d: string | Date | null | undefined): string {
    if (!d) return new Date().toISOString();
    if (typeof d === 'string') return d;
    return d.toISOString();
}

export function toCef(ioc: SiemIOC): string {
    const sev = ioc.severity ? SEVERITY_TO_CEF[ioc.severity.toLowerCase()] ?? 5 : 5;
    const sig = ioc.threatType?.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'ioc';
    const name = `IOC observed: ${ioc.type}`;
    const cefField = IOC_TYPE_TO_CEF_FIELD[ioc.type.toLowerCase()] ?? 'cs1';

    const ext: string[] = [];
    ext.push(`${cefField}=${escapeCefExt(ioc.value)}`);
    if (cefField === 'cs1') ext.push('cs1Label=iocValue');
    ext.push(`externalId=${escapeCefExt(ioc.id)}`);
    ext.push(`cat=${escapeCefExt(ioc.threatType || 'threat-intelligence')}`);
    if (ioc.source) ext.push(`deviceCustomString2=${escapeCefExt(ioc.source)}`,
                              `cs2Label=feedSource`);
    if (typeof ioc.confidence === 'number') ext.push(`cn1=${ioc.confidence}`, 'cn1Label=confidence');
    ext.push(`rt=${Date.parse(isoOrNow(ioc.lastSeen)) || Date.now()}`);

    return [
        `CEF:0`,
        escapeCefHeader(VENDOR),
        escapeCefHeader(PRODUCT),
        escapeCefHeader(VERSION),
        escapeCefHeader(sig),
        escapeCefHeader(name),
        String(sev),
        ext.join(' '),
    ].join('|');
}

// ============================================================================
// LEEF v2 — pipe-delimited header + custom-delim key=value extensions
// ============================================================================

const LEEF_DELIM = '\t';

function escapeLeefExt(s: string): string {
    // LEEF: only the delimiter and newline need escaping inside values.
    return s.replace(/\r?\n/g, ' ').replace(new RegExp(LEEF_DELIM, 'g'), ' ');
}

export function toLeef(ioc: SiemIOC): string {
    const sev = ioc.severity ? SEVERITY_TO_CEF[ioc.severity.toLowerCase()] ?? 5 : 5;
    const eventId = ioc.threatType?.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'ioc';
    const cefField = IOC_TYPE_TO_CEF_FIELD[ioc.type.toLowerCase()] ?? 'iocValue';

    const ext: string[] = [];
    ext.push(`devTime=${isoOrNow(ioc.lastSeen)}`);
    ext.push(`severity=${sev}`);
    ext.push(`cat=${escapeLeefExt(ioc.threatType || 'threat-intelligence')}`);
    ext.push(`${cefField}=${escapeLeefExt(ioc.value)}`);
    ext.push(`externalId=${escapeLeefExt(ioc.id)}`);
    if (ioc.source) ext.push(`feedSource=${escapeLeefExt(ioc.source)}`);
    if (typeof ioc.confidence === 'number') ext.push(`confidence=${ioc.confidence}`);

    // LEEF:2.0|Vendor|Product|Version|EventID|delim|Extension
    return [
        'LEEF:2.0',
        VENDOR,
        PRODUCT,
        VERSION,
        eventId,
        'x09', // signals literal HT (\t) as the delimiter — per IBM doc §LEEF 2.0
        ext.join(LEEF_DELIM),
    ].join('|');
}

// ============================================================================
// ECS — Elastic Common Schema (flat JSON)
// ============================================================================

export interface EcsDoc {
    '@timestamp': string;
    event: { kind: string; category: string[]; type: string[]; severity?: number; provider: string };
    threat: { indicator: Record<string, unknown> };
    tags?: string[];
    rinjani: { id: string; source?: string | null; firstSeen?: string; lastSeen?: string };
}

export function toEcs(ioc: SiemIOC): EcsDoc {
    const ts = isoOrNow(ioc.lastSeen);
    const indicator: Record<string, unknown> = {
        type: ioc.type,
        confidence: typeof ioc.confidence === 'number' ? ioc.confidence : undefined,
        description: ioc.threatType || undefined,
    };

    // ECS-specific shape per IOC type
    switch (ioc.type.toLowerCase()) {
        case 'ip':
        case 'ipv4':
        case 'ipv6':
            indicator.ip = ioc.value;
            break;
        case 'domain':
        case 'hostname':
            indicator.domain = ioc.value;
            break;
        case 'url':
            indicator.url = { full: ioc.value };
            break;
        case 'email':
            indicator.email = { address: ioc.value };
            break;
        case 'hash':
        case 'hash-md5':
        case 'md5':
            indicator.file = { hash: { md5: ioc.value } };
            break;
        case 'hash-sha1':
        case 'sha1':
            indicator.file = { hash: { sha1: ioc.value } };
            break;
        case 'hash-sha256':
        case 'sha256':
            indicator.file = { hash: { sha256: ioc.value } };
            break;
        default:
            indicator.value = ioc.value;
    }

    return {
        '@timestamp': ts,
        event: {
            kind: 'enrichment',
            category: ['threat'],
            type: ['indicator'],
            severity: ioc.severity ? SEVERITY_TO_CEF[ioc.severity.toLowerCase()] : undefined,
            provider: VENDOR,
        },
        threat: { indicator },
        tags: ioc.tags ?? undefined,
        rinjani: {
            id: ioc.id,
            source: ioc.source,
            firstSeen: ioc.firstSeen ? isoOrNow(ioc.firstSeen) : undefined,
            lastSeen: ioc.lastSeen ? isoOrNow(ioc.lastSeen) : undefined,
        },
    };
}

/** Serialise to NDJSON suitable for Elastic `_bulk` or Beats `filestream` input. */
export function ecsToNdjson(docs: EcsDoc[]): string {
    return docs.map(d => JSON.stringify(d)).join('\n') + (docs.length > 0 ? '\n' : '');
}

// ============================================================================
// Batch helpers
// ============================================================================

export function toCefBatch(iocs: SiemIOC[]): string {
    return iocs.map(toCef).join('\n') + (iocs.length > 0 ? '\n' : '');
}

export function toLeefBatch(iocs: SiemIOC[]): string {
    return iocs.map(toLeef).join('\n') + (iocs.length > 0 ? '\n' : '');
}
