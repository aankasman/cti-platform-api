/**
 * Exa AI — Search API
 */

import { getExa } from './client';

export interface ExaSearchOptions {
    query: string;
    numResults?: number;
    type?: 'neural' | 'keyword' | 'auto';
    includeText?: boolean;
    includeSummary?: boolean;
    includeHighlights?: boolean;
    startPublishedDate?: string;
    endPublishedDate?: string;
}

/**
 * Execute a real-time Exa Search query (synchronous, fast).
 */
export async function searchWeb(opts: ExaSearchOptions) {
    const exa = getExa();

    const searchOpts: Record<string, unknown> = {
        numResults: opts.numResults || 10,
        type: opts.type || 'auto',
        contents: {
            text: opts.includeText !== false ? true : undefined,
            summary: { query: opts.query },
            highlights: opts.includeHighlights !== false ? { query: opts.query } : undefined,
        },
        startPublishedDate: opts.startPublishedDate,
        endPublishedDate: opts.endPublishedDate,
    };

    const result = await exa.search(opts.query, searchOpts);

    return {
        results: result.results.map((r: Record<string, unknown>) => ({
            title: r.title,
            url: r.url,
            publishedDate: r.publishedDate,
            author: r.author,
            text: r.text,
            summary: r.summary,
            highlights: r.highlights,
            highlightScores: r.highlightScores,
        })),
        requestId: result.requestId,
        costDollars: result.costDollars,
    };
}

/**
 * Search specifically for threat intelligence content.
 */
export async function searchThreats(query: string, numResults: number = 10) {
    return searchWeb({
        query: `Cybersecurity threat intelligence: ${query}`,
        numResults,
        type: 'neural',
        includeText: true,
        includeSummary: true,
        includeHighlights: true,
    });
}
