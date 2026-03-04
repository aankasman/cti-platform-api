/**
 * OpenSearch Service — Barrel Re-export
 *
 * Provides full-text search capabilities using OpenSearch.
 * Handles indexing, searching, faceted aggregations, and vector search.
 */

// Client & infrastructure
export { getOpenSearchClient, checkHealth, createIndices, INDICES } from './opensearch/client';

// Bulk & single-document indexing
export {
    indexIOCs, indexVulnerabilities, indexActors,
    indexSingleIOC, indexSingleVulnerability, indexSingleActor,
    deleteDocument, reindexAll,
    mapIOCToDocument, mapVulnerabilityToDocument, mapActorToDocument,
} from './opensearch/indexing';

// Unified search
export { unifiedSearch, getById } from './opensearch/search';
export type { SearchOptions, SearchResult } from './opensearch/search';

// Aggregations
export { getCounts, getIOCDistribution, getSourceBreakdown, getThreatHeatmap, getDateHistogram, getBatchedStats } from './opensearch/aggregations';
export type { EntityCounts, BatchedStatsResult } from './opensearch/aggregations';

// Vector search
export { vectorSearch, findSimilar, recreateIndex } from './opensearch/vector';
export type { VectorSearchResult } from './opensearch/vector';
