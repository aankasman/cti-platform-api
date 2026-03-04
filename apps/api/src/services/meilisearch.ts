/**
 * Meilisearch Service — Typo-Tolerant Instant Search
 *
 * Complements OpenSearch (primary data store) with a fast, typo-tolerant
 * search layer for the dashboard's search bar. Indexes lightweight
 * documents from OpenSearch for instant UX.
 *
 * Indexed collections:
 *   - iocs: Indicator values + types + risk scores
 *   - cves: CVE IDs + descriptions + CVSS scores
 *   - actors: Threat actor names + aliases + origins
 *
 * Usage:
 *   const results = await meiliSearch.search('emotet', { limit: 10 });
 *   await meiliSearch.indexIOC({ id: '...', value: '...', ... });
 */

import { createLogger } from '../lib/logger';

const log = createLogger('Meilisearch');

// ============================================================================
// Types
// ============================================================================

export interface MeiliConfig {
    host: string;
    apiKey: string;
}

export interface MeiliDocument {
    id: string;
    type: 'ioc' | 'cve' | 'actor';
    title: string;
    description?: string;
    value?: string;
    riskScore?: number;
    tags?: string[];
    updatedAt: string;
}

export interface MeiliSearchResult {
    hits: MeiliDocument[];
    query: string;
    processingTimeMs: number;
    estimatedTotalHits: number;
}

// ============================================================================
// Meilisearch Client
// ============================================================================

const DEFAULT_CONFIG: MeiliConfig = {
    host: process.env.MEILI_URL || 'http://localhost:7700',
    apiKey: process.env.MEILI_MASTER_KEY || 'rinjani-meili-dev-key',
};

const INDEX_NAME = 'cti_search';

class MeilisearchService {
    private config: MeiliConfig;
    private available: boolean | null = null;

    constructor(config?: Partial<MeiliConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    private async request(path: string, options: RequestInit = {}): Promise<unknown> {
        const res = await fetch(`${this.config.host}${path}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.apiKey}`,
                ...options.headers,
            },
            signal: AbortSignal.timeout(10_000),
        });

        if (!res.ok) {
            const body = await res.text();
            throw new Error(`Meilisearch error ${res.status}: ${body}`);
        }

        return res.json();
    }

    /**
     * Check if Meilisearch is reachable
     */
    async isAvailable(): Promise<boolean> {
        if (this.available !== null) return this.available;

        try {
            await this.request('/health');
            this.available = true;
            log.info('Meilisearch is available');
        } catch {
            this.available = false;
            log.info('Meilisearch unavailable (platform profile not active)');
        }

        return this.available;
    }

    /**
     * Initialize the index with searchable/filterable attributes
     */
    async setupIndex(): Promise<void> {
        if (!(await this.isAvailable())) return;

        try {
            // Create index
            await this.request('/indexes', {
                method: 'POST',
                body: JSON.stringify({
                    uid: INDEX_NAME,
                    primaryKey: 'id',
                }),
            }).catch(() => { /* index may already exist */ });

            // Configure searchable attributes (priority order)
            await this.request(`/indexes/${INDEX_NAME}/settings`, {
                method: 'PATCH',
                body: JSON.stringify({
                    searchableAttributes: ['title', 'value', 'description', 'tags'],
                    filterableAttributes: ['type', 'riskScore', 'tags'],
                    sortableAttributes: ['riskScore', 'updatedAt'],
                    rankingRules: [
                        'words',
                        'typo',
                        'proximity',
                        'attribute',
                        'sort',
                        'exactness',
                        'riskScore:desc',
                    ],
                    typoTolerance: {
                        enabled: true,
                        minWordSizeForTypos: {
                            oneTypo: 4,
                            twoTypos: 8,
                        },
                    },
                }),
            });

            log.info('Meilisearch index configured', { index: INDEX_NAME });
        } catch (err) {
            log.warn('Failed to setup Meilisearch index', { error: (err as Error).message });
        }
    }

    /**
     * Universal search across all CTI types
     */
    async search(query: string, options?: {
        limit?: number;
        offset?: number;
        filter?: string;
        sort?: string[];
    }): Promise<MeiliSearchResult> {
        if (!(await this.isAvailable())) {
            return { hits: [], query, processingTimeMs: 0, estimatedTotalHits: 0 };
        }

        try {
            const result = await this.request(`/indexes/${INDEX_NAME}/search`, {
                method: 'POST',
                body: JSON.stringify({
                    q: query,
                    limit: options?.limit || 20,
                    offset: options?.offset || 0,
                    filter: options?.filter,
                    sort: options?.sort,
                    attributesToHighlight: ['title', 'value', 'description'],
                    highlightPreTag: '<mark>',
                    highlightPostTag: '</mark>',
                }),
            }) as { hits: MeiliDocument[]; query: string; processingTimeMs: number; estimatedTotalHits?: number };

            return {
                hits: result.hits,
                query: result.query,
                processingTimeMs: result.processingTimeMs,
                estimatedTotalHits: result.estimatedTotalHits || 0,
            };
        } catch (err) {
            log.warn('Meilisearch query failed', { query, error: (err as Error).message });
            return { hits: [], query, processingTimeMs: 0, estimatedTotalHits: 0 };
        }
    }

    /**
     * Index a batch of documents
     */
    async indexDocuments(documents: MeiliDocument[]): Promise<void> {
        if (!(await this.isAvailable()) || documents.length === 0) return;

        try {
            await this.request(`/indexes/${INDEX_NAME}/documents`, {
                method: 'POST',
                body: JSON.stringify(documents),
            });
            log.debug('Indexed documents to Meilisearch', { count: documents.length });
        } catch (err) {
            log.warn('Failed to index to Meilisearch', { error: (err as Error).message });
        }
    }

    /**
     * Remove a document by ID
     */
    async removeDocument(id: string): Promise<void> {
        if (!(await this.isAvailable())) return;

        try {
            await this.request(`/indexes/${INDEX_NAME}/documents/${id}`, {
                method: 'DELETE',
            });
        } catch { /* ignore */ }
    }

    /**
     * Get index stats
     */
    async getStats(): Promise<{
        numberOfDocuments: number;
        isIndexing: boolean;
    } | null> {
        if (!(await this.isAvailable())) return null;

        try {
            return await this.request(`/indexes/${INDEX_NAME}/stats`) as { numberOfDocuments: number; isIndexing: boolean };
        } catch {
            return null;
        }
    }

    resetAvailability(): void {
        this.available = null;
    }
}

// Singleton
export const meiliSearch = new MeilisearchService();
