/**
 * STIX 2.1 Export Service
 * 
 * Converts internal threat intelligence data to STIX 2.1 format.
 * Supports bundling IOCs, Threat Actors, and Vulnerabilities.
 * 
 * STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
 */

import { db } from '@rinjani/db';
import { iocs, vulnerabilities, threatActors } from '@rinjani/db/schema';
import { desc, sql, eq, like, and, or } from 'drizzle-orm';
import {
    buildProvenance,
    SOURCE_IDENTITIES,
    TLP_MARKINGS,
    PLATFORM_IDENTITY,
    type STIXIdentity as ProvIdentity,
    type STIXMarking,
    type STIXProvenance,
} from './stixProvenance';

// ---------------------------------------------------------------------------
// Per-source TLP defaults.
//   - Public OSINT feeds (alienvault, threatfox, urlhaus, abuse.ch) → WHITE
//   - Premium / community-restricted (virustotal, abuseipdb) → GREEN
//   - Internal / manual / sensitive → AMBER (caller-overridable)
// Caller can override per-bundle via STIXExportOptions.defaultTlp.
// Per-IOC TLP is supported when ioc.tlp is set (pulses already carry it;
// extending iocs.tlp is a one-line follow-up).
// ---------------------------------------------------------------------------
const SOURCE_TLP_DEFAULT: Record<string, 'white' | 'green' | 'amber' | 'red'> = {
    alienvault: 'white',
    threatfox: 'white',
    urlhaus: 'white',
    malwarebazaar: 'white',
    abusessl: 'white',
    cisa: 'white',
    nvd: 'white',
    epss: 'white',
    virustotal: 'green',
    abuseipdb: 'green',
    shodan: 'green',
    greynoise: 'green',
    urlscan: 'green',
    misp: 'amber',
};

function resolveTlp(source: string | null | undefined, perRecord: string | null | undefined, fallback: string): string {
    if (perRecord && perRecord.toLowerCase() in TLP_MARKINGS) return perRecord.toLowerCase();
    const key = (source || '').toLowerCase();
    if (key in SOURCE_TLP_DEFAULT) return SOURCE_TLP_DEFAULT[key];
    return fallback;
}

// ============================================================================
// STIX 2.1 Types
// ============================================================================

interface STIXBundle {
    type: 'bundle';
    id: string;
    spec_version: '2.1';
    objects: STIXObject[];
}

interface STIXObject {
    type: string;
    spec_version: '2.1';
    id: string;
    created: string;
    /** Optional — marking-definition objects are immutable per STIX 2.1 §4.7 */
    modified?: string;
    [key: string]: unknown;
}

interface STIXMixin {
    /** Identity SDO id of the producer. */
    created_by_ref?: string;
    /** TLP / statement marking-definition ids attached to this object. */
    object_marking_refs?: string[];
    /** STIX 2.1 confidence (0-100). */
    confidence?: number;
    /** Custom `extension-definition--provenance` lineage data. */
    extensions?: STIXProvenance['extensions'];
}

interface STIXIndicator extends STIXObject, STIXMixin {
    type: 'indicator';
    name?: string;
    description?: string;
    pattern: string;
    pattern_type: 'stix' | 'pcre' | 'sigma' | 'snort' | 'suricata' | 'yara';
    pattern_version?: string;
    valid_from: string;
    valid_until?: string;
    indicator_types?: string[];
    kill_chain_phases?: Array<{ kill_chain_name: string; phase_name: string }>;
    labels?: string[];
    external_references?: STIXExternalReference[];
}

interface STIXThreatActor extends STIXObject, STIXMixin {
    type: 'threat-actor';
    name: string;
    description?: string;
    threat_actor_types?: string[];
    aliases?: string[];
    roles?: string[];
    goals?: string[];
    sophistication?: string;
    resource_level?: string;
    primary_motivation?: string;
    secondary_motivations?: string[];
    labels?: string[];
    external_references?: STIXExternalReference[];
}

interface STIXVulnerability extends STIXObject, STIXMixin {
    type: 'vulnerability';
    name: string;
    description?: string;
    external_references: STIXExternalReference[];
}

interface STIXExternalReference {
    source_name: string;
    url?: string;
    external_id?: string;
    description?: string;
}

interface STIXIdentity extends STIXObject {
    type: 'identity';
    name: string;
    identity_class: 'organization' | 'individual' | 'system';
}

// ============================================================================
// Helpers
// ============================================================================

function generateSTIXId(type: string, uuid?: string): string {
    const id = uuid || crypto.randomUUID();
    return `${type}--${id}`;
}

function toISOString(date: Date | string | null | undefined): string {
    if (!date) return new Date().toISOString();
    if (typeof date === 'string') return date;
    return date.toISOString();
}

// ============================================================================
// IOC Type to STIX Pattern Mapping
// ============================================================================

const IOC_TYPE_TO_STIX_PATTERN: Record<string, (value: string) => string> = {
    'ip': (v) => `[ipv4-addr:value = '${v}']`,
    'ipv4': (v) => `[ipv4-addr:value = '${v}']`,
    'ipv6': (v) => `[ipv6-addr:value = '${v}']`,
    'domain': (v) => `[domain-name:value = '${v}']`,
    'hostname': (v) => `[domain-name:value = '${v}']`,
    'url': (v) => `[url:value = '${v}']`,
    'hash-md5': (v) => `[file:hashes.MD5 = '${v}']`,
    'hash-sha1': (v) => `[file:hashes.'SHA-1' = '${v}']`,
    'hash-sha256': (v) => `[file:hashes.'SHA-256' = '${v}']`,
    'md5': (v) => `[file:hashes.MD5 = '${v}']`,
    'sha1': (v) => `[file:hashes.'SHA-1' = '${v}']`,
    'sha256': (v) => `[file:hashes.'SHA-256' = '${v}']`,
    'email': (v) => `[email-addr:value = '${v}']`,
};

const THREAT_TYPE_TO_INDICATOR_TYPE: Record<string, string[]> = {
    'malware': ['malicious-activity'],
    'c2': ['malicious-activity', 'command-and-control'],
    'phishing': ['malicious-activity', 'phishing'],
    'ransomware': ['malicious-activity', 'ransomware'],
    'botnet': ['malicious-activity', 'botnet'],
    'apt': ['attribution'],
};

// ============================================================================
// Converters
// ============================================================================

function iocToSTIXIndicator(ioc: any, defaultTlp = 'white'): STIXIndicator | null {
    const patternFn = IOC_TYPE_TO_STIX_PATTERN[ioc.type];
    if (!patternFn) {
        // Unknown IOC type, skip
        return null;
    }

    const pattern = patternFn(ioc.value);
    const indicatorTypes = THREAT_TYPE_TO_INDICATOR_TYPE[ioc.threatType || ''] || ['anomalous-activity'];
    const confidence = typeof ioc.confidence === 'number' ? ioc.confidence : 50;
    const tlp = resolveTlp(ioc.source, ioc.tlp, defaultTlp);
    const provenance = buildProvenance(ioc.source || 'rinjani', confidence, tlp);

    return {
        type: 'indicator',
        spec_version: '2.1',
        id: generateSTIXId('indicator', ioc.id),
        created: toISOString(ioc.createdAt),
        modified: toISOString(ioc.updatedAt),
        name: `${ioc.type.toUpperCase()}: ${ioc.value}`,
        description: `${ioc.threatType || 'Unknown'} indicator from ${ioc.source}`,
        pattern,
        pattern_type: 'stix',
        valid_from: toISOString(ioc.firstSeen || ioc.createdAt),
        valid_until: ioc.lastSeen ? toISOString(new Date(new Date(ioc.lastSeen).getTime() + 90 * 24 * 60 * 60 * 1000)) : undefined,
        indicator_types: indicatorTypes,
        labels: ioc.tags || [],
        confidence,
        created_by_ref: provenance.created_by_ref,
        object_marking_refs: provenance.object_marking_refs,
        external_references: [{
            source_name: ioc.source,
            description: `Ingested from ${ioc.source}`,
        }],
        extensions: provenance.extensions,
    };
}

function threatActorToSTIX(actor: any, defaultTlp = 'white'): STIXThreatActor {
    const source = (actor.source || 'misp').toLowerCase();
    const confidence = parseConfidenceWord(actor.confidence) ?? 50;
    const tlp = resolveTlp(source, actor.tlp, defaultTlp);
    const provenance = buildProvenance(source, confidence, tlp);

    return {
        type: 'threat-actor',
        spec_version: '2.1',
        id: actor.stixId || generateSTIXId('threat-actor', actor.id),
        created: toISOString(actor.stixCreated || actor.createdAt),
        modified: toISOString(actor.stixModified || actor.updatedAt),
        name: actor.name,
        description: actor.description || undefined,
        aliases: actor.aliases || [],
        goals: actor.goals || [],
        sophistication: actor.sophistication || undefined,
        resource_level: actor.resourceLevel || undefined,
        primary_motivation: actor.primaryMotivation || undefined,
        secondary_motivations: actor.secondaryMotivations || [],
        labels: actor.labels || [],
        confidence,
        created_by_ref: provenance.created_by_ref,
        object_marking_refs: provenance.object_marking_refs,
        external_references: (actor.externalReferences || []).map((ref: any) => ({
            source_name: ref.source_name || 'unknown',
            url: ref.url,
            external_id: ref.external_id,
        })),
        extensions: provenance.extensions,
    };
}

function vulnerabilityToSTIX(vuln: any, defaultTlp = 'white'): STIXVulnerability {
    const refs: STIXExternalReference[] = [
        {
            source_name: 'cve',
            external_id: vuln.cveId,
            url: `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`,
        },
    ];

    if (vuln.isExploited) {
        refs.push({
            source_name: 'cisa-kev',
            description: 'CISA Known Exploited Vulnerability',
            url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        });
    }

    const source = vuln.source || (vuln.isExploited ? 'cisa' : 'nvd');
    const confidence = vuln.epssScore != null ? Math.round(vuln.epssScore * 100) : 90;
    const tlp = resolveTlp(source, vuln.tlp, defaultTlp);
    const provenance = buildProvenance(source, confidence, tlp);

    return {
        type: 'vulnerability',
        spec_version: '2.1',
        id: generateSTIXId('vulnerability', vuln.id),
        created: toISOString(vuln.createdAt),
        modified: toISOString(vuln.updatedAt || vuln.lastModified),
        name: vuln.cveId,
        description: vuln.description || undefined,
        confidence,
        created_by_ref: provenance.created_by_ref,
        object_marking_refs: provenance.object_marking_refs,
        external_references: refs,
        extensions: provenance.extensions,
    };
}

/**
 * Threat actors use a word confidence ('low' | 'medium' | 'high' | 'verified')
 * stored in a VARCHAR(20). Translate to STIX's 0-100 integer scale.
 */
function parseConfidenceWord(c: unknown): number | null {
    if (typeof c === 'number') return Math.max(0, Math.min(100, c));
    if (typeof c !== 'string') return null;
    switch (c.toLowerCase()) {
        case 'verified': return 95;
        case 'high':     return 80;
        case 'medium':   return 55;
        case 'low':      return 25;
        default:         return null;
    }
}

// ============================================================================
// Bundle Generator
// ============================================================================

export interface STIXExportOptions {
    includeIOCs?: boolean;
    includeThreatActors?: boolean;
    includeVulnerabilities?: boolean;
    iocLimit?: number;
    threatActorLimit?: number;
    vulnerabilityLimit?: number;
    // Filters
    iocType?: string;
    iocSource?: string;
    severity?: string;
    /**
     * Default TLP marking applied when an object has no per-record TLP and
     * its source isn't in SOURCE_TLP_DEFAULT. STIX 2.1 standard TLP set:
     * 'white' | 'green' | 'amber' | 'red'. Default: 'white'.
     */
    defaultTlp?: 'white' | 'green' | 'amber' | 'red';
}

const RINJANI_IDENTITY: STIXIdentity = {
    type: 'identity',
    spec_version: '2.1',
    id: 'identity--rinjani-analytics',
    created: '2026-01-01T00:00:00.000Z',
    modified: new Date().toISOString(),
    name: 'RinjaniAnalytics CTI Platform',
    identity_class: 'system',
};

export async function generateSTIXBundle(options: STIXExportOptions = {}): Promise<STIXBundle> {
    const {
        includeIOCs = true,
        includeThreatActors = true,
        includeVulnerabilities = true,
        iocLimit = 1000,
        threatActorLimit = 100,
        vulnerabilityLimit = 500,
        iocType,
        iocSource,
        severity,
        defaultTlp = 'white',
    } = options;

    // Producer identity always appears as the first object; per-object
    // identities + TLP markings collect into a Set and get appended at the
    // end so each appears once even when referenced by thousands of objects.
    const objects: STIXObject[] = [RINJANI_IDENTITY];
    const referencedIdentityIds = new Set<string>();
    const referencedMarkingIds = new Set<string>();

    // Export IOCs as Indicators
    if (includeIOCs) {
        let iocQuery = db.select().from(iocs);

        const conditions: any[] = [];
        if (iocType) conditions.push(eq(iocs.type, iocType));
        if (iocSource) conditions.push(eq(iocs.source, iocSource));
        if (severity) conditions.push(eq(iocs.severity, severity));

        if (conditions.length > 0) {
            iocQuery = iocQuery.where(and(...conditions)) as typeof iocQuery;
        }

        const iocRecords = await iocQuery
            .orderBy(desc(iocs.createdAt))
            .limit(iocLimit);

        for (const ioc of iocRecords) {
            const indicator = iocToSTIXIndicator(ioc, defaultTlp);
            if (indicator) {
                objects.push(indicator);
                if (indicator.created_by_ref) referencedIdentityIds.add(indicator.created_by_ref);
                for (const m of indicator.object_marking_refs ?? []) referencedMarkingIds.add(m);
            }
        }
    }

    // Export Threat Actors
    if (includeThreatActors) {
        const actorRecords = await db.select()
            .from(threatActors)
            .orderBy(desc(threatActors.createdAt))
            .limit(threatActorLimit);

        for (const actor of actorRecords) {
            const stix = threatActorToSTIX(actor, defaultTlp);
            objects.push(stix);
            if (stix.created_by_ref) referencedIdentityIds.add(stix.created_by_ref);
            for (const m of stix.object_marking_refs ?? []) referencedMarkingIds.add(m);
        }
    }

    // Export Vulnerabilities
    if (includeVulnerabilities) {
        let vulnQuery = db.select().from(vulnerabilities);

        if (severity) {
            vulnQuery = vulnQuery.where(eq(vulnerabilities.severity, severity)) as typeof vulnQuery;
        }

        const vulnRecords = await vulnQuery
            .orderBy(desc(vulnerabilities.createdAt))
            .limit(vulnerabilityLimit);

        for (const vuln of vulnRecords) {
            const stix = vulnerabilityToSTIX(vuln, defaultTlp);
            objects.push(stix);
            if (stix.created_by_ref) referencedIdentityIds.add(stix.created_by_ref);
            for (const m of stix.object_marking_refs ?? []) referencedMarkingIds.add(m);
        }
    }

    // Append referenced identities (skip the Rinjani identity already at head)
    referencedIdentityIds.delete(RINJANI_IDENTITY.id);
    referencedIdentityIds.delete(PLATFORM_IDENTITY.id);
    for (const id of referencedIdentityIds) {
        const ident = identityById(id);
        if (ident) objects.push(ident as unknown as STIXObject);
    }
    // Append referenced TLP marking-definitions (no `modified` per STIX 2.1)
    for (const id of referencedMarkingIds) {
        const marking = markingById(id);
        if (marking) objects.push(marking as unknown as STIXObject);
    }

    return {
        type: 'bundle',
        id: generateSTIXId('bundle'),
        spec_version: '2.1',
        objects,
    };
}

// Lookup helpers — keyed by STIX id so the bundle can deduplicate refs.
function identityById(id: string): ProvIdentity | null {
    for (const ident of Object.values(SOURCE_IDENTITIES)) {
        if (ident.id === id) return ident;
    }
    if (id === PLATFORM_IDENTITY.id) return PLATFORM_IDENTITY;
    return null;
}

function markingById(id: string): STIXMarking | null {
    for (const m of Object.values(TLP_MARKINGS)) {
        if (m.id === id) return m;
    }
    return null;
}

// ============================================================================
// Single Object Export
// ============================================================================

export async function getIOCAsSTIX(iocId: string): Promise<STIXIndicator | null> {
    const [ioc] = await db.select().from(iocs).where(eq(iocs.id, iocId)).limit(1);
    if (!ioc) return null;
    return iocToSTIXIndicator(ioc);
}

export async function getThreatActorAsSTIX(actorId: string): Promise<STIXThreatActor | null> {
    const [actor] = await db.select().from(threatActors).where(eq(threatActors.id, actorId)).limit(1);
    if (!actor) return null;
    return threatActorToSTIX(actor);
}

export async function getVulnerabilityAsSTIX(vulnId: string): Promise<STIXVulnerability | null> {
    const [vuln] = await db.select().from(vulnerabilities).where(eq(vulnerabilities.id, vulnId)).limit(1);
    if (!vuln) return null;
    return vulnerabilityToSTIX(vuln);
}
