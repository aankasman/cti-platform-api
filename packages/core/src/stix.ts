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
    modified: string;
    [key: string]: unknown;
}

interface STIXIndicator extends STIXObject {
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
    confidence?: number;
    external_references?: STIXExternalReference[];
}

interface STIXThreatActor extends STIXObject {
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

interface STIXVulnerability extends STIXObject {
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

function iocToSTIXIndicator(ioc: any): STIXIndicator | null {
    const patternFn = IOC_TYPE_TO_STIX_PATTERN[ioc.type];
    if (!patternFn) {
        // Unknown IOC type, skip
        return null;
    }

    const pattern = patternFn(ioc.value);
    const indicatorTypes = THREAT_TYPE_TO_INDICATOR_TYPE[ioc.threatType || ''] || ['anomalous-activity'];

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
        confidence: ioc.confidence || undefined,
        external_references: [{
            source_name: ioc.source,
            description: `Ingested from ${ioc.source}`,
        }],
    };
}

function threatActorToSTIX(actor: any): STIXThreatActor {
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
        external_references: (actor.externalReferences || []).map((ref: any) => ({
            source_name: ref.source_name || 'unknown',
            url: ref.url,
            external_id: ref.external_id,
        })),
    };
}

function vulnerabilityToSTIX(vuln: any): STIXVulnerability {
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

    return {
        type: 'vulnerability',
        spec_version: '2.1',
        id: generateSTIXId('vulnerability', vuln.id),
        created: toISOString(vuln.createdAt),
        modified: toISOString(vuln.updatedAt || vuln.lastModified),
        name: vuln.cveId,
        description: vuln.description || undefined,
        external_references: refs,
    };
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
    } = options;

    const objects: STIXObject[] = [RINJANI_IDENTITY];

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
            const indicator = iocToSTIXIndicator(ioc);
            if (indicator) {
                objects.push(indicator);
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
            objects.push(threatActorToSTIX(actor));
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
            objects.push(vulnerabilityToSTIX(vuln));
        }
    }

    return {
        type: 'bundle',
        id: generateSTIXId('bundle'),
        spec_version: '2.1',
        objects,
    };
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
