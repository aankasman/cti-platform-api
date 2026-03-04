/**
 * SearXNG — Types & Configuration
 */

export const SEARXNG_URL = process.env.SEARXNG_URL || 'http://localhost:8080';
export const DEFAULT_TIMEOUT = 12000;

export interface SearXNGResult {
    url: string;
    title: string;
    content: string;
    engine: string;
    engines: string[];
    publishedDate?: string;
    category: string;
    score: number;
    thumbnail?: string;
}

export interface SearXNGResponse {
    query: string;
    number_of_results: number;
    results: SearXNGResult[];
    suggestions: string[];
    infoboxes: Record<string, unknown>[];
}

export interface SearchOptions {
    numResults?: number;
    categories?: string[];
    engines?: string[];
    timeRange?: string;
    language?: string;
    safeSearch?: 0 | 1 | 2;
}

/** Normalized result matching frontend expectations (Exa-compatible shape) */
export interface NexusSearchResult {
    url: string;
    title: string;
    summary: string;
    text?: string;
    publishedDate?: string;
    source: string;
    engines: string[];
    score: number;
    highlights?: string[];
}
