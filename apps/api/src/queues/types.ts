/**
 * BullMQ Job Data Types
 */

export interface FeedSyncJobData {
    source: string;  // feed source key — must match a registry entry or 'all'
    options?: {
        limit?: number;
        since?: string; // ISO date
    };
}

export interface EnrichmentJobData {
    iocId: string;
    iocValue: string;
    iocType: string;
    sources?: string[];
}

export interface AIAnalysisJobData {
    iocId: string;
    iocValue: string;
    analysisType: 'threat-assessment' | 'malware-classification' | 'risk-score';
}

export interface NotificationJobData {
    channel: 'slack' | 'email' | 'webhook';
    target: string;
    payload: {
        type: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        title: string;
        message: string;
        data?: Record<string, unknown>;
    };
}

export interface AlertJobData {
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    type: 'ioc_detected' | 'feed_sync_failed' | 'high_risk_ioc' | 'system_alert' | 'system_event' | 'enrichment_complete';
    title: string;
    message: string;
    source?: string;
    metadata?: Record<string, unknown>;
}

export interface Neo4jSyncJobData {
    syncType: 'full' | 'actors' | 'techniques' | 'malware' | 'tools' | 'relationships' | 'pulses-iocs' | 'all-iocs' | 'cves' | 'similarity';
    options?: {
        maxPulses?: number;
        maxCVEs?: number;
        maxIOCs?: number;
        minScore?: number;
        topK?: number;
        batchSize?: number;
    };
}

export interface WebSearchJobData {
    query: string;
    numResults: number;
    provider: 'searxng' | 'exa';
    categories?: string[];
    timeRange?: string;
    persist: boolean;
    extractIOCs: boolean;
    correlationId: string;
    createdAt: string;
}

export interface NexusJobData {
    type: 'webhook-item' | 'sync-webset' | 'sync-all-websets' | 'process-item' | 'enrich-item' | 'persist-scrape' | 'batch-scrape';
    websetId?: string;
    itemId?: string;
    category?: string;
    payload?: Record<string, unknown>;
    /** URLs to scrape in background (used by batch-scrape) */
    urls?: string[];
    /** Original search query (used by batch-scrape for context) */
    query?: string;
}

export interface CVEEnrichmentJobData {
    type: 'cvss' | 'dates' | 'all';
    batchSize?: number;
}
