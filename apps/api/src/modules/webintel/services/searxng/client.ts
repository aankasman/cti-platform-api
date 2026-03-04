/**
 * SearXNG — API Client & Result Normalization
 */

import type { SearXNGResponse, SearXNGResult, SearchOptions, NexusSearchResult } from './types';
import { SEARXNG_URL, DEFAULT_TIMEOUT } from './types';

export async function querySearXNG(query: string, opts: SearchOptions = {}): Promise<SearXNGResponse> {
    const params = new URLSearchParams({
        q: query,
        format: 'json',
    });

    if (opts.categories?.length) {
        params.set('categories', opts.categories.join(','));
    }
    if (opts.engines?.length) {
        params.set('engines', opts.engines.join(','));
    }
    if (opts.timeRange) {
        params.set('time_range', opts.timeRange);
    }
    if (opts.language) {
        params.set('language', opts.language);
    }
    if (opts.safeSearch !== undefined) {
        params.set('safesearch', String(opts.safeSearch));
    }

    const url = `${SEARXNG_URL}/search?${params.toString()}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT);

    try {
        const res = await fetch(url, {
            signal: controller.signal,
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!res.ok) {
            const errText = await res.text().catch(() => '');
            throw new Error(`SearXNG error ${res.status}: ${errText}`);
        }

        return await res.json() as SearXNGResponse;
    } finally {
        clearTimeout(timeout);
    }
}

/**
 * Convert SearXNG results to Nexus-standard format (Exa-compatible).
 * Deduplicates by URL and limits to numResults.
 */
export function normalizeResults(results: SearXNGResult[], numResults: number): NexusSearchResult[] {
    const seen = new Set<string>();
    const normalized: NexusSearchResult[] = [];

    for (const r of results) {
        if (!r.url || seen.has(r.url)) continue;
        seen.add(r.url);

        let hostname = '';
        try {
            hostname = new URL(r.url).hostname;
        } catch { /* ignore invalid URLs */ }

        normalized.push({
            url: r.url,
            title: r.title || 'Untitled',
            summary: r.content || '',
            publishedDate: r.publishedDate || undefined,
            source: hostname,
            engines: r.engines || [r.engine],
            score: r.score || 0,
            highlights: r.content ? [r.content] : [],
        });

        if (normalized.length >= numResults) break;
    }

    return normalized;
}
