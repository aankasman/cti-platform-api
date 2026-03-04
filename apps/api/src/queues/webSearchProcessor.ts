/**
 * Web Search Worker — Search Processor
 *
 * Handles SearXNG query execution and result normalization.
 */

import { createLogger } from '../lib/logger';
import { ExternalServiceError } from '../lib/errors';
import * as searxng from '../services/searxng';
import type { WebSearchJobData, WebSearchResult } from '../lib/schemas';

const log = createLogger('WebSearchWorker:search');

/**
 * Execute a web search and normalize results.
 */
export async function executeSearch(
    data: WebSearchJobData,
    correlationId: string,
): Promise<{ searchResult: Awaited<ReturnType<typeof searxng.searchWeb>>; startTime: number }> {
    const startTime = Date.now();

    try {
        const searchResult = await searxng.searchWeb(data.query, {
            numResults: Math.min(data.numResults, 25),
            categories: data.categories || ['general'],
            timeRange: data.timeRange,
        });

        log.info('SearXNG search completed', {
            resultCount: searchResult.results.length,
            iocCount: searchResult.iocs?.length ?? 0,
        });

        return { searchResult, startTime };
    } catch (err) {
        throw new ExternalServiceError('SearXNG', err instanceof Error ? err : undefined);
    }
}

/**
 * Build normalized WebSearchResult from raw search results.
 */
export function buildResult(
    searchResult: Awaited<ReturnType<typeof searxng.searchWeb>>,
    data: WebSearchJobData,
    startTime: number,
): WebSearchResult {
    return {
        items: searchResult.results.map((r) => ({
            title: r.title || 'Untitled',
            url: r.url,
            snippet: r.summary || '',
            source: r.source || data.provider,
            publishedDate: r.publishedDate,
        })),
        iocs: data.extractIOCs ? searchResult.iocs : undefined,
        iocStats: data.extractIOCs && searchResult.iocStats
            ? { total: searchResult.iocStats.total, duplicatesRemoved: searchResult.iocStats.duplicatesRemoved, ...searchResult.iocStats.byType }
            : undefined,
        provider: data.provider,
        query: data.query,
        totalResults: searchResult.results.length,
        processingTimeMs: Date.now() - startTime,
    };
}
