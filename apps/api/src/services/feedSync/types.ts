/**
 * Feed Sync Types
 */

export interface OTXPulse {
    id: string;
    name: string;
    description: string;
    author_name: string;
    created: string;
    modified: string;
    indicators: OTXIndicator[];
    tags: string[];
    targeted_countries: string[];
    malware_families: string[];
    attack_ids: string[];
    references: string[];
    tlp: string;
}

export interface OTXIndicator {
    id: number;
    indicator: string;
    type: string;
    created: string;
    content: string;
    title: string;
    description: string;
    is_active: number;
}

export interface OTXSyncOptions {
    limit?: number;
    since?: string;
    modifiedSince?: string;
}

export interface SyncResult {
    success: boolean;
    pulsesProcessed: number;
    indicatorsProcessed: number;  // Total from API
    indicatorsAdded: number;      // Actually new (delta)
    indicatorsUpdated: number;
    errors: string[];
    /**
     * Total rows actually written to ANY table during the sync — IOCs +
     * pulses + galaxy_clusters + threat_actors + techniques + whatever the
     * feed touches. Optional because the field is new; older callers don't
     * populate it. When present, the feed-sync worker uses this for
     * `feed_sync_runs.items_ingested` instead of `indicatorsAdded`, which
     * is IOC-centric and reads 0 for feeds that mostly write to ancillary
     * tables (e.g., MISP Galaxy adds ~10k galaxy_cluster rows per cycle —
     * the dashboard previously showed "0 items" for those runs because
     * `indicatorsAdded` was 0). Falls back to `indicatorsAdded` when unset.
     */
    totalRowsAffected?: number;
    pulses?: Array<{ id: string; name: string; indicatorCount: number }>;
    /** Actual indicator data for auto-enrichment (limited to first N) */
    indicators?: Array<{ id: string; value: string; type: string }>;
}

export interface CISAVulnerability {
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse?: string;
    notes?: string;
}
