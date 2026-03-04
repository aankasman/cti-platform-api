/**
 * OpenSearch Aggregations — Stats, distributions, heatmaps, histograms
 */

import { getOpenSearchClient, INDICES } from './client';

interface OSBucket {
    key: string;
    key_as_string?: string;
    doc_count: number;
    [nested: string]: unknown;
}

// ============================================================================
// Aggregation Functions (for Stats)
// ============================================================================

export interface EntityCounts {
    iocs: number;
    vulnerabilities: number;
    actors: number;
    total: number;
}

/**
 * Get document counts per entity type using OpenSearch aggregations
 * Replaces 5x DB COUNT(*) queries with single OpenSearch query
 */
export async function getCounts(): Promise<EntityCounts> {
    const client = getOpenSearchClient();

    try {
        const response = await client.search({
            index: INDICES.unified,
            body: {
                size: 0,
                aggs: {
                    by_entity: { terms: { field: 'entityType.keyword', size: 10 } }
                }
            }
        });

        const buckets = response.body.aggregations?.by_entity?.buckets || [];
        const countMap: Record<string, number> = {};

        for (const bucket of buckets) {
            countMap[bucket.key] = bucket.doc_count;
        }

        const total = typeof response.body.hits.total === 'number'
            ? response.body.hits.total
            : response.body.hits.total?.value || 0;

        return {
            iocs: countMap['ioc'] || 0,
            vulnerabilities: countMap['vulnerability'] || 0,
            actors: countMap['threat-actor'] || countMap['actor'] || 0,
            total,
        };
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) {
            return { iocs: 0, vulnerabilities: 0, actors: 0, total: 0 };
        }
        throw error;
    }
}

/**
 * Get IOC distribution by type
 * Replaces DB GROUP BY iocs.type query
 */
export async function getIOCDistribution(days?: number): Promise<Array<{ name: string; value: number }>> {
    const client = getOpenSearchClient();

    try {
        const query: Record<string, unknown> = days
            ? {
                bool: {
                    filter: [
                        { term: { 'entityType.keyword': 'ioc' } },
                        { range: { createdAt: { gte: `now-${days}d/d` } } },
                    ]
                }
            }
            : { term: { 'entityType.keyword': 'ioc' } };

        const response = await client.search({
            index: INDICES.unified,
            body: {
                size: 0,
                query,
                aggs: {
                    by_type: { terms: { field: 'type.keyword', size: 50 } }
                }
            }
        });

        const buckets = response.body.aggregations?.by_type?.buckets || [];
        return buckets.map((b: OSBucket) => ({ name: b.key, value: b.doc_count }));
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) return [];
        throw error;
    }
}

/**
 * Get IOC breakdown by source
 * Replaces DB GROUP BY iocs.source query
 */
export async function getSourceBreakdown(days?: number): Promise<Array<{ source: string; count: number }>> {
    const client = getOpenSearchClient();

    try {
        const query: Record<string, unknown> = days
            ? {
                bool: {
                    filter: [
                        { term: { 'entityType.keyword': 'ioc' } },
                        { range: { createdAt: { gte: `now-${days}d/d` } } },
                    ]
                }
            }
            : { term: { 'entityType.keyword': 'ioc' } };

        const response = await client.search({
            index: INDICES.unified,
            body: {
                size: 0,
                query,
                aggs: {
                    by_source: { terms: { field: 'source.keyword', size: 50 } }
                }
            }
        });

        const buckets = response.body.aggregations?.by_source?.buckets || [];
        return buckets.map((b: OSBucket) => ({ source: b.key, count: b.doc_count }));
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) return [];
        throw error;
    }
}

/**
 * Get threat heatmap (IOCs by type × severity)
 * Replaces DB GROUP BY iocs.type, iocs.severity query
 */
export async function getThreatHeatmap(days?: number): Promise<Array<{ type: string; severity: string; count: number }>> {
    const client = getOpenSearchClient();

    try {
        const query: Record<string, unknown> = days
            ? {
                bool: {
                    filter: [
                        { term: { 'entityType.keyword': 'ioc' } },
                        { range: { createdAt: { gte: `now-${days}d/d` } } },
                    ]
                }
            }
            : { term: { 'entityType.keyword': 'ioc' } };

        const response = await client.search({
            index: INDICES.unified,
            body: {
                size: 0,
                query,
                aggs: {
                    by_type: {
                        terms: { field: 'type.keyword', size: 20 },
                        aggs: {
                            by_severity: { terms: { field: 'severity.keyword', size: 10 } }
                        }
                    }
                }
            }
        });

        const result: Array<{ type: string; severity: string; count: number }> = [];
        const typeBuckets = response.body.aggregations?.by_type?.buckets || [];

        for (const typeBucket of typeBuckets) {
            const severityBuckets = typeBucket.by_severity?.buckets || [];
            for (const sevBucket of severityBuckets) {
                if (sevBucket.key) {
                    result.push({
                        type: typeBucket.key,
                        severity: sevBucket.key,
                        count: sevBucket.doc_count,
                    });
                }
            }
        }

        return result;
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) return [];
        throw error;
    }
}

// ============================================================================
// Batched Aggregations (saves multiple round-trips)
// ============================================================================

export interface BatchedStatsResult {
    distribution: Array<{ name: string; value: number }>;
    sourceBreakdown: Array<{ source: string; count: number }>;
    heatmap: Array<{ type: string; severity: string; count: number }>;
}

/**
 * Get IOC distribution, source breakdown, and threat heatmap in a SINGLE query.
 * Replaces 3 separate OpenSearch calls with 1 — saves 2 round-trips.
 */
export async function getBatchedStats(): Promise<BatchedStatsResult> {
    const client = getOpenSearchClient();

    try {
        const response = await client.search({
            index: INDICES.unified,
            body: {
                size: 0,
                query: { term: { 'entityType.keyword': 'ioc' } },
                aggs: {
                    by_type: {
                        terms: { field: 'type.keyword', size: 50 },
                        aggs: {
                            by_severity: { terms: { field: 'severity.keyword', size: 10 } },
                        },
                    },
                    by_source: { terms: { field: 'source.keyword', size: 50 } },
                },
            },
        });

        // Parse distribution (from by_type buckets)
        const typeBuckets = response.body.aggregations?.by_type?.buckets || [];
        const distribution = typeBuckets.map((b: OSBucket) => ({ name: b.key, value: b.doc_count }));

        // Parse source breakdown (from by_source buckets)
        const sourceBuckets = response.body.aggregations?.by_source?.buckets || [];
        const sourceBreakdown = sourceBuckets.map((b: OSBucket) => ({ source: b.key, count: b.doc_count }));

        // Parse heatmap (from nested by_type → by_severity)
        const heatmap: Array<{ type: string; severity: string; count: number }> = [];
        for (const typeBucket of typeBuckets) {
            const severityBuckets = typeBucket.by_severity?.buckets || [];
            for (const sevBucket of severityBuckets) {
                if (sevBucket.key) {
                    heatmap.push({
                        type: typeBucket.key,
                        severity: sevBucket.key,
                        count: sevBucket.doc_count,
                    });
                }
            }
        }

        return { distribution, sourceBreakdown, heatmap };
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) {
            return { distribution: [], sourceBreakdown: [], heatmap: [] };
        }
        throw error;
    }
}

/**
 * Get date histogram for severity trends
 * Provides real data instead of mock random values
 */
export async function getDateHistogram(days: number = 30): Promise<Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
}>> {
    const client = getOpenSearchClient();

    try {
        const dateFrom = new Date();
        dateFrom.setDate(dateFrom.getDate() - days);

        const response = await client.search({
            index: INDICES.unified,
            body: {
                size: 0,
                query: {
                    bool: {
                        must: [
                            { term: { 'entityType.keyword': 'ioc' } },
                            { range: { updatedAt: { gte: dateFrom.toISOString() } } }
                        ]
                    }
                },
                aggs: {
                    by_date: {
                        date_histogram: {
                            field: 'updatedAt',
                            calendar_interval: 'day',
                            format: 'yyyy-MM-dd',
                            min_doc_count: 0,
                            extended_bounds: {
                                min: dateFrom.toISOString().split('T')[0],
                                max: new Date().toISOString().split('T')[0]
                            }
                        },
                        aggs: {
                            by_severity: { terms: { field: 'severity.keyword', size: 10 } }
                        }
                    }
                }
            }
        });

        const buckets = response.body.aggregations?.by_date?.buckets || [];
        return buckets.map((b: OSBucket) => {
            const severities: Record<string, number> = {};
            for (const sev of ((b.by_severity as { buckets: OSBucket[] })?.buckets || [])) {
                severities[sev.key as string] = sev.doc_count as number;
            }
            return {
                date: b.key_as_string,
                critical: severities['critical'] || 0,
                high: severities['high'] || 0,
                medium: severities['medium'] || 0,
                low: severities['low'] || 0,
            };
        });
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) return [];
        throw error;
    }
}
