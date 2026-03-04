/**
 * OpenSearch Service — Barrel Re-export
 *
 * Provides full-text search capabilities using OpenSearch.
 * Handles indexing, searching, faceted aggregations, and vector search.
 */

// Client & infrastructure
export { getOpenSearchClient, checkHealth, createIndices, INDICES } from '../../../services/opensearch/client';

// Bulk & single-document indexing
export {
    indexIOCs, indexVulnerabilities, indexActors,
    indexSingleIOC, indexSingleVulnerability, indexSingleActor,
    deleteDocument, reindexAll,
    mapIOCToDocument, mapVulnerabilityToDocument, mapActorToDocument,
} from '../../../services/opensearch/indexing';

// Unified search
export { unifiedSearch, getById } from '../../../services/opensearch/search';
export type { SearchOptions, SearchResult } from '../../../services/opensearch/search';

// Aggregations
export { getCounts, getIOCDistribution, getSourceBreakdown, getThreatHeatmap, getDateHistogram, getBatchedStats } from '../../../services/opensearch/aggregations';
export type { EntityCounts, BatchedStatsResult } from '../../../services/opensearch/aggregations';

// Vector search
export { vectorSearch, findSimilar, recreateIndex } from '../../../services/opensearch/vector';
export type { VectorSearchResult } from '../../../services/opensearch/vector';
