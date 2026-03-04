/**
 * STIX 2.1 Provenance & Data Lineage
 *
 * Implements the STIX 2.1 data marking and provenance model:
 *   - created_by_ref: Identity of the data provider
 *   - object_marking_refs: TLP and statement markings
 *   - granular_markings: Per-field classification
 *   - external_references: Source URLs and IDs
 *
 * This module transforms internal IOC/CVE/Actor records into
 * STIX 2.1 compliant objects with full provenance chain.
 *
 * Reference: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
 */

import { createLogger } from '../../../lib/logger';

const log = createLogger('STIXProvenance');

// ============================================================================
// STIX 2.1 Types
// ============================================================================

export interface STIXIdentity {
    type: 'identity';
    spec_version: '2.1';
    id: string;
    created: string;
    modified: string;
    name: string;
    identity_class: 'organization' | 'individual' | 'system';
    sectors?: string[];
    contact_information?: string;
}

export interface STIXMarking {
    type: 'marking-definition';
    spec_version: '2.1';
    id: string;
    created: string;
    definition_type: 'tlp' | 'statement';
    definition: {
        tlp?: 'white' | 'green' | 'amber' | 'red';
        statement?: string;
    };
}

export interface STIXExternalReference {
    source_name: string;
    url?: string;
    external_id?: string;
    description?: string;
}

export interface STIXProvenance {
    created_by_ref: string;
    object_marking_refs: string[];
    external_references: STIXExternalReference[];
    labels: string[];
    confidence: number;
    lang: string;
    /** Custom extension: provenance chain from multiple sources */
    extensions?: {
        'extension-definition--provenance': {
            extension_type: 'property-extension';
            sources: ProvenanceSource[];
            merge_history: MergeEvent[];
            data_quality: DataQuality;
        };
    };
}

export interface ProvenanceSource {
    source_name: string;
    source_type: 'feed' | 'manual' | 'enrichment' | 'correlation';
    identity_ref: string;
    first_observed: string | null;
    last_observed: string | null;
    confidence: number;
    external_references: STIXExternalReference[];
}

export interface MergeEvent {
    timestamp: string;
    action: 'created' | 'merged' | 'enriched' | 'updated';
    source: string;
    fields_updated: string[];
}

export interface DataQuality {
    completeness: number;  // 0-100: how many fields are populated
    corroboration: number; // Number of independent sources
    freshness: number;     // 0-100: time-decayed freshness
    overall: number;       // Weighted composite
}

// ============================================================================
// Standard Identity Definitions (Data Providers)
// ============================================================================

const PLATFORM_IDENTITY: STIXIdentity = {
    type: 'identity',
    spec_version: '2.1',
    id: 'identity--rinjani-platform',
    created: '2024-01-01T00:00:00.000Z',
    modified: new Date().toISOString(),
    name: 'RinjaniAnalytics CTI Platform',
    identity_class: 'system',
    sectors: ['technology'],
};

const SOURCE_IDENTITIES: Record<string, STIXIdentity> = {
    alienvault: {
        type: 'identity', spec_version: '2.1',
        id: 'identity--alienvault-otx',
        created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z',
        name: 'AlienVault OTX', identity_class: 'organization',
    },
    virustotal: {
        type: 'identity', spec_version: '2.1',
        id: 'identity--virustotal',
        created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z',
        name: 'VirusTotal', identity_class: 'organization',
    },
    abuseipdb: {
        type: 'identity', spec_version: '2.1',
        id: 'identity--abuseipdb',
        created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z',
        name: 'AbuseIPDB', identity_class: 'organization',
    },
    threatfox: {
        type: 'identity', spec_version: '2.1',
        id: 'identity--threatfox',
        created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z',
        name: 'ThreatFox (abuse.ch)', identity_class: 'organization',
    },
    misp: {
        type: 'identity', spec_version: '2.1',
        id: 'identity--misp',
        created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z',
        name: 'MISP', identity_class: 'organization',
    },
};

// ============================================================================
// TLP Marking Definitions (standard STIX 2.1)
// ============================================================================

const TLP_MARKINGS: Record<string, STIXMarking> = {
    white: {
        type: 'marking-definition', spec_version: '2.1',
        id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        created: '2017-01-20T00:00:00.000Z',
        definition_type: 'tlp', definition: { tlp: 'white' },
    },
    green: {
        type: 'marking-definition', spec_version: '2.1',
        id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        created: '2017-01-20T00:00:00.000Z',
        definition_type: 'tlp', definition: { tlp: 'green' },
    },
    amber: {
        type: 'marking-definition', spec_version: '2.1',
        id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
        created: '2017-01-20T00:00:00.000Z',
        definition_type: 'tlp', definition: { tlp: 'amber' },
    },
    red: {
        type: 'marking-definition', spec_version: '2.1',
        id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
        created: '2017-01-20T00:00:00.000Z',
        definition_type: 'tlp', definition: { tlp: 'red' },
    },
};

// ============================================================================
// Provenance Builder
// ============================================================================

/**
 * Build STIX 2.1 provenance metadata for an IOC.
 */
export function buildProvenance(
    source: string,
    confidence: number = 50,
    tlp: string = 'white',
    additionalSources?: ProvenanceSource[],
): STIXProvenance {
    const sourceIdentity = SOURCE_IDENTITIES[source.toLowerCase()] || {
        type: 'identity' as const, spec_version: '2.1' as const,
        id: `identity--${source.toLowerCase()}`,
        created: '2024-01-01T00:00:00.000Z', modified: '2024-01-01T00:00:00.000Z',
        name: source, identity_class: 'organization' as const,
    };

    const tlpMarking = TLP_MARKINGS[tlp.toLowerCase()] || TLP_MARKINGS.white;
    const allSources = additionalSources || [];

    // Primary source
    const primarySource: ProvenanceSource = {
        source_name: source,
        source_type: 'feed',
        identity_ref: sourceIdentity.id,
        first_observed: null,
        last_observed: null,
        confidence,
        external_references: [],
    };

    // Data quality assessment
    const corroboration = 1 + allSources.length;
    const dataQuality: DataQuality = {
        completeness: 0, // Calculated by caller
        corroboration,
        freshness: 100, // Freshest at creation
        overall: Math.round((confidence * 0.4) + (corroboration * 10 * 0.3) + (100 * 0.3)),
    };

    return {
        created_by_ref: sourceIdentity.id,
        object_marking_refs: [tlpMarking.id],
        external_references: [],
        labels: [],
        confidence,
        lang: 'en',
        extensions: {
            'extension-definition--provenance': {
                extension_type: 'property-extension',
                sources: [primarySource, ...allSources],
                merge_history: [{
                    timestamp: new Date().toISOString(),
                    action: 'created',
                    source,
                    fields_updated: ['*'],
                }],
                data_quality: dataQuality,
            },
        },
    };
}

/**
 * Record a merge event in the provenance chain
 */
export function addMergeEvent(
    existing: STIXProvenance,
    action: MergeEvent['action'],
    source: string,
    fieldsUpdated: string[],
): STIXProvenance {
    const ext = existing.extensions?.['extension-definition--provenance'];
    if (!ext) return existing;

    ext.merge_history.push({
        timestamp: new Date().toISOString(),
        action,
        source,
        fields_updated: fieldsUpdated,
    });

    // Update corroboration count
    const uniqueSources = new Set(ext.sources.map(s => s.source_name));
    ext.data_quality.corroboration = uniqueSources.size;
    ext.data_quality.overall = Math.round(
        (existing.confidence * 0.4)
        + (uniqueSources.size * 10 * 0.3)
        + (ext.data_quality.freshness * 0.3),
    );

    return existing;
}

/**
 * Calculate data completeness for an entity
 */
export function calculateCompleteness(entity: Record<string, unknown>, requiredFields: string[]): number {
    const populated = requiredFields.filter(f => {
        const val = entity[f];
        return val !== null && val !== undefined && val !== '' && !(Array.isArray(val) && val.length === 0);
    });
    return Math.round((populated.length / requiredFields.length) * 100);
}

// ============================================================================
// Exports
// ============================================================================

export {
    PLATFORM_IDENTITY,
    SOURCE_IDENTITIES,
    TLP_MARKINGS,
};
