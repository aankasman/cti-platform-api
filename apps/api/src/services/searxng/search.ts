/**
 * SearXNG — Search Functions
 */

import { extractIOCs } from '../iocExtractor';
import type { ExtractedIOC } from '../iocExtractor';
import type { SearchOptions, NexusSearchResult } from './types';
import { querySearXNG, normalizeResults } from './client';

/**
 * General web search via SearXNG.
 */
export async function searchWeb(
    query: string,
    opts: SearchOptions = {},
): Promise<{ results: NexusSearchResult[]; iocs: ExtractedIOC[]; iocStats: { total: number; byType: Record<string, number>; duplicatesRemoved: number }; query: string }> {
    const raw = await querySearXNG(query, {
        categories: opts.categories || ['general'],
        ...opts,
    });

    const results = normalizeResults(raw.results, opts.numResults || 10);

    // Extract IOCs from all result snippets
    const allText = results.map(r => [r.title, r.summary, r.text].filter(Boolean).join('\n')).join('\n\n');
    const iocResult = extractIOCs(allText);

    return {
        results,
        iocs: iocResult.iocs,
        iocStats: iocResult.stats,
        query: raw.query,
    };
}

/**
 * News-focused search.
 */
export async function searchNews(
    query: string,
    opts: SearchOptions = {},
): Promise<{ results: NexusSearchResult[]; iocs: ExtractedIOC[]; iocStats: { total: number; byType: Record<string, number>; duplicatesRemoved: number }; query: string }> {
    return searchWeb(query, {
        ...opts,
        categories: ['news'],
    });
}

/**
 * Social media / forum search (Reddit, forums).
 */
export async function searchSocial(
    query: string,
    opts: SearchOptions = {},
): Promise<{ results: NexusSearchResult[]; iocs: ExtractedIOC[]; iocStats: { total: number; byType: Record<string, number>; duplicatesRemoved: number }; query: string }> {
    return searchWeb(query, {
        ...opts,
        categories: ['social media'],
        engines: ['reddit', ...(opts.engines || [])],
    });
}

/**
 * IT / Security-focused search (GitHub, Stack Overflow, etc.).
 */
export async function searchIT(
    query: string,
    opts: SearchOptions = {},
): Promise<{ results: NexusSearchResult[]; iocs: ExtractedIOC[]; iocStats: { total: number; byType: Record<string, number>; duplicatesRemoved: number }; query: string }> {
    return searchWeb(query, {
        ...opts,
        categories: ['it'],
        engines: ['github', 'stackoverflow', ...(opts.engines || [])],
    });
}
