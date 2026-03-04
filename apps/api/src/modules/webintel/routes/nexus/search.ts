/**
 * Nexus Search Routes
 *
 * Real-time web search (SearXNG default, Exa opt-in) and CTI-focused search.
 * After search, queues background scraping of all result URLs for persistence.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import * as exa from '../../../../services/exa';
import * as searxng from '../../../../services/searxng';
import { extractIOCs } from '../../../../services/iocExtractor';
import { ValidationError } from '../../../../lib/errors';
import { createLogger } from '../../../../lib/logger';
import { SearchSchema, ThreatSearchSchema } from './schemas';
import { nexusQueue } from '../../../../queues';

const router = new Hono();
const log = createLogger('Nexus:search');

/**
 * Enqueue background scraping of search result URLs.
 * Fire-and-forget — never blocks the search response.
 */
async function enqueueBackgroundScrape(urls: string[], query: string): Promise<void> {
    if (urls.length === 0) return;
    try {
        await nexusQueue.add(`batch-scrape-${Date.now()}`, {
            type: 'batch-scrape' as const,
            urls,
            query,
        }, {
            priority: 5, // lower priority than interactive scrapes
        });
        log.info('Queued background scrape for search results', { urlCount: urls.length, query });
    } catch (err) {
        log.warn('Failed to queue background scrape (non-blocking)', { error: (err as Error).message });
    }
}

/**
 * POST /search - Search the web in real-time
 */
router.post('/search', async (c: Context) => {
    const body = await c.req.json();
    const parsed = SearchSchema.safeParse(body);
    if (!parsed.success) {
        throw new ValidationError(
            parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
        );
    }
    const { query, numResults, provider, categories, timeRange, type, includeText } = parsed.data;

    if (provider === 'exa') {
        const result = await exa.searchWeb({
            query,
            numResults,
            type: (type || 'auto') as 'keyword' | 'neural' | 'auto',
            includeText: includeText !== false,
            includeSummary: true,
            includeHighlights: true,
        });

        const allTexts = result.results.map((r: Record<string, unknown>) => [r.title, r.text, r.summary].filter(Boolean).join('\n'));
        const iocs = extractIOCs(allTexts.join('\n\n'));

        // Background scrape Exa result URLs too
        const urls = result.results.map((r: Record<string, unknown>) => r.url).filter(Boolean) as string[];
        enqueueBackgroundScrape(urls, query);

        return c.json({
            success: true,
            data: {
                results: result.results,
                iocs: iocs.iocs,
                iocStats: iocs.stats,
                provider: 'exa',
                requestId: result.requestId,
                costDollars: result.costDollars,
            },
        });
    }

    // Default: SearXNG (free, self-hosted)
    const result = await searxng.searchWeb(query, {
        numResults,
        categories: categories || ['general'],
        timeRange,
    });

    // Background scrape all result URLs for persistence
    const urls = result.results.map(r => r.url).filter(Boolean);
    enqueueBackgroundScrape(urls, query);

    return c.json({
        success: true,
        data: {
            results: result.results,
            iocs: result.iocs,
            iocStats: result.iocStats,
            provider: 'searxng',
            costDollars: 0,
        },
    });
});

/**
 * POST /search/threats - CTI-focused search
 */
router.post('/search/threats', async (c: Context) => {
    const body = await c.req.json();
    const parsed = ThreatSearchSchema.safeParse(body);
    if (!parsed.success) {
        throw new ValidationError(
            parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
        );
    }
    const { query, numResults, provider } = parsed.data;

    if (provider === 'exa') {
        const result = await exa.searchThreats(query, numResults);
        const allTexts = result.results.map((r: Record<string, unknown>) => [r.title, r.text, r.summary].filter(Boolean).join('\n'));
        const iocs = extractIOCs(allTexts.join('\n\n'));

        const urls = result.results.map((r: Record<string, unknown>) => r.url).filter(Boolean) as string[];
        enqueueBackgroundScrape(urls, query);

        return c.json({
            success: true,
            data: {
                results: result.results,
                iocs: iocs.iocs,
                iocStats: iocs.stats,
                provider: 'exa',
                costDollars: result.costDollars,
            },
        });
    }

    // SearXNG + news category for CTI
    const result = await searxng.searchWeb(
        `${query} cybersecurity threat vulnerability malware`,
        { numResults, categories: ['general', 'news'] },
    );

    const urls = result.results.map(r => r.url).filter(Boolean);
    enqueueBackgroundScrape(urls, query);

    return c.json({
        success: true,
        data: {
            results: result.results,
            iocs: result.iocs,
            iocStats: result.iocStats,
            provider: 'searxng',
            costDollars: 0,
        },
    });
});

export default router;

