/**
 * SearXNG — Content Scraping & HTML Utilities
 */

import { extractIOCs } from '../iocExtractor';
import type { ExtractedIOC } from '../iocExtractor';
import { DEFAULT_TIMEOUT } from './types';

/**
 * Fetch a URL and extract text content + IOCs.
 */
export async function scrapeAndExtract(url: string): Promise<{
    url: string;
    title: string;
    text: string;
    iocs: ExtractedIOC[];
    iocStats: { total: number; byType: Record<string, number>; duplicatesRemoved: number };
    fetchedAt: string;
}> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT);

    try {
        const res = await fetch(url, {
            signal: controller.signal,
            headers: {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
        });

        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const html = await res.text();
        const title = extractTitle(html);
        const text = htmlToText(html);

        const iocResult = extractIOCs(text);

        return {
            url,
            title,
            text: text.slice(0, 10000),
            iocs: iocResult.iocs,
            iocStats: iocResult.stats,
            fetchedAt: new Date().toISOString(),
        };
    } finally {
        clearTimeout(timeout);
    }
}

// =============================================================================
// HTML Utilities
// =============================================================================

function extractTitle(html: string): string {
    const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return match ? match[1].trim() : 'Untitled';
}

function htmlToText(html: string): string {
    return html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<!--[\s\S]*?-->/g, '')
        .replace(/<\/(p|div|h[1-6]|li|tr|br|hr)[^>]*>/gi, '\n')
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&nbsp;/g, ' ')
        .replace(/[ \t]+/g, ' ')
        .replace(/\n\s*\n/g, '\n\n')
        .trim();
}

// =============================================================================
// Health Check
// =============================================================================

import { SEARXNG_URL } from './types';

export async function checkHealth(): Promise<{
    available: boolean;
    url: string;
    error?: string;
}> {
    try {
        const res = await fetch(`${SEARXNG_URL}/search?q=test&format=json`, {
            signal: AbortSignal.timeout(5000),
            headers: { 'Accept': 'application/json' },
        });

        return {
            available: res.ok,
            url: SEARXNG_URL,
        };
    } catch (err) {
        return {
            available: false,
            url: SEARXNG_URL,
            error: (err as Error).message,
        };
    }
}
