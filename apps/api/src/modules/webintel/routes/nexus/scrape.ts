/**
 * Nexus Scrape Route
 *
 * Deep scrape a URL, extract IOCs, and optionally summarize with AI.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import * as searxng from '../../../../services/searxng';
import * as aiMW from '../../../../services/aiMiddleware';
import type { ExtractedEntities } from '../../../../services/aiMiddleware/helpers';
import { saveScrapeResult } from '../../../../services/webIntelPersist';
import { alertsQueue } from '../../../../queues';
import { ValidationError } from '../../../../lib/errors';
import { createLogger } from '../../../../lib/logger';
import { ScrapeSchema, LookupSchema } from './schemas';
import { db, eq } from '@rinjani/db';
import { webIntelItems, webIntelMentions } from '@rinjani/db/schema';

const router = new Hono();
const log = createLogger('Nexus:scrape');

/**
 * POST /scrape - Deep scrape a URL, extract IOCs, and optionally summarize with AI
 *
 * Returns partial results on failure (scrape may succeed but AI may fail, or vice versa).
 */
router.post('/scrape', async (c: Context) => {
    const body = await c.req.json();
    const parsed = ScrapeSchema.safeParse(body);
    if (!parsed.success) {
        throw new ValidationError(
            parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
        );
    }
    const { url, summarize, extractEntities } = parsed.data;

    const status: { scrape: string; ai: string; entityExtraction: string } = {
        scrape: 'pending',
        ai: summarize ? 'pending' : 'skipped',
        entityExtraction: extractEntities ? 'pending' : 'skipped',
    };

    let scraped: Awaited<ReturnType<typeof searxng.scrapeAndExtract>> | null = null;
    let aiSummary: string | undefined;
    let entities: ExtractedEntities | undefined;
    let scrapeError: string | undefined;

    // Step 1: Scrape the URL
    try {
        scraped = await searxng.scrapeAndExtract(url);
        status.scrape = 'success';
    } catch (err) {
        status.scrape = 'failed';
        scrapeError = (err as Error).message || 'Failed to fetch URL';
        log.error('Failed to scrape URL', err, { url });
    }

    // Step 2: AI summarize (only if scrape succeeded and has text)
    if (summarize && scraped?.text) {
        try {
            aiSummary = await aiMW.summarizeContent(scraped.text);
            status.ai = 'success';
        } catch (err) {
            status.ai = 'failed';
            log.warn('AI summarize failed', { url, error: (err as Error).message });
        }
    } else if (summarize && !scraped?.text) {
        status.ai = 'skipped_no_content';
    }

    // Step 3: Entity extraction (only if scrape succeeded and has text)
    if (extractEntities && scraped?.text) {
        try {
            entities = await aiMW.extractEntities(scraped.text);
            status.entityExtraction = 'success';
        } catch (err) {
            status.entityExtraction = 'failed';
            log.warn('Entity extraction failed', { url, error: (err as Error).message });
        }
    } else if (extractEntities && !scraped?.text) {
        status.entityExtraction = 'skipped_no_content';
    }

    // Step 4: Persist to PostgreSQL + queue Neo4j/OpenSearch sync
    let saved = false;
    let itemId: string | undefined;
    let isNew = false;

    if (status.scrape === 'success') {
        try {
            const saveResult = await saveScrapeResult({
                url,
                title: scraped?.title,
                text: scraped?.text,
                aiSummary,
                entities: entities as Record<string, string[]> | undefined,
                iocs: scraped?.iocs as Record<string, string[]> | undefined,
                iocStats: scraped?.iocStats as Record<string, number> | undefined,
                fetchedAt: scraped?.fetchedAt,
            });
            saved = true;
            itemId = saveResult.itemId;
            isNew = saveResult.isNew;
            log.info('Saved scrape to DB', { itemId, isNew, mentions: saveResult.mentionsCreated });

            // Fire immediate bell notification
            await alertsQueue.add(`scrape-saved-${itemId}`, {
                severity: 'info',
                type: 'system_event',
                title: `Deep Scrape: ${scraped?.title || url}`,
                message: isNew
                    ? `New intelligence saved — ${saveResult.mentionsCreated} IOC mentions extracted. AI analysis and graph sync queued.`
                    : `Intelligence updated — ${saveResult.mentionsCreated} IOC mentions. Re-processing queued.`,
                source: 'nexus-scrape',
                metadata: { itemId, url, isNew, mentionsCreated: saveResult.mentionsCreated },
            });
        } catch (err) {
            log.warn('Persistence failed (non-blocking)', { url, error: (err as Error).message });
        }
    }

    // Always return a response — never 500
    return c.json({
        success: status.scrape === 'success',
        data: {
            url,
            title: scraped?.title || 'Untitled',
            text: scraped?.text || '',
            iocs: scraped?.iocs || {},
            iocStats: scraped?.iocStats || {},
            fetchedAt: scraped?.fetchedAt || new Date().toISOString(),
            aiSummary,
            entities,
            status,
            error: scrapeError,
            saved,
            itemId,
            isNew,
        },
    });
});

/**
 * GET /lookup?url= - Check if a URL has been scraped and return cached content
 *
 * Returns cached title, text, AI summary, IOC mentions, and timestamps.
 * If the URL hasn't been scraped yet, returns { found: false }.
 */
router.get('/lookup', async (c: Context) => {
    const url = c.req.query('url');
    const parsed = LookupSchema.safeParse({ url });
    if (!parsed.success) {
        throw new ValidationError(
            parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
        );
    }

    const [item] = await db.select()
        .from(webIntelItems)
        .where(eq(webIntelItems.url, parsed.data.url))
        .limit(1);

    if (!item) {
        return c.json({ success: true, data: { found: false } });
    }

    // Fetch IOC mentions for this item
    const mentions = await db.select()
        .from(webIntelMentions)
        .where(eq(webIntelMentions.itemId, item.id));

    // Group IOCs by type for the response
    const iocs: Record<string, string[]> = {};
    for (const m of mentions) {
        if (!iocs[m.type]) iocs[m.type] = [];
        iocs[m.type].push(m.value);
    }

    return c.json({
        success: true,
        data: {
            found: true,
            itemId: item.id,
            url: item.url,
            title: item.title,
            text: item.textContent,
            summary: item.summary,
            iocs,
            iocCount: mentions.length,
            scrapedAt: item.createdAt,
            updatedAt: item.updatedAt,
        },
    });
});

export default router;
