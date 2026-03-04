/**
 * Web Intelligence Persistence — Synchronous PostgreSQL Save
 */

import { db, eq } from '@rinjani/db';
import { webIntelItems, webIntelMentions } from '@rinjani/db/schema';
import { nexusQueue } from '../../queues';
import { createLogger } from '../../lib/logger';
import type { ScrapeData, SaveResult } from './types';
import { detectPlatform } from './helpers';

const log = createLogger('WebIntelPersist');

/**
 * Save a scrape result to PostgreSQL and queue background processing.
 * Deduplicates by URL — if the same URL was scraped before, updates it.
 */
export async function saveScrapeResult(data: ScrapeData): Promise<SaveResult> {
    // 1. Dedup check by URL
    const existing = await db.select({ id: webIntelItems.id })
        .from(webIntelItems)
        .where(eq(webIntelItems.url, data.url))
        .limit(1);

    let itemId: string;
    let isNew = true;

    if (existing.length > 0) {
        // Update existing record
        itemId = existing[0].id;
        isNew = false;

        await db.update(webIntelItems)
            .set({
                title: data.title || undefined,
                textContent: data.text?.slice(0, 50000),
                summary: data.summary || undefined,
                aiSummary: data.aiSummary || undefined,
                extractedEntities: data.entities || {},
                iocExtracted: true,
                sourceProvider: 'searxng',
                updatedAt: new Date(),
            })
            .where(eq(webIntelItems.id, itemId));

        log.info('Updated existing item', { itemId, url: data.url });
    } else {
        // Insert new record
        const platform = detectPlatform(data.url);
        const [inserted] = await db.insert(webIntelItems)
            .values({
                category: 'osint-scrape',
                title: data.title || 'Untitled',
                url: data.url,
                sourceUrl: data.url,
                textContent: data.text?.slice(0, 50000),
                summary: data.summary || undefined,
                aiSummary: data.aiSummary || undefined,
                extractedEntities: data.entities || {},
                iocExtracted: true,
                sourceProvider: 'searxng',
                platform,
                publishedAt: data.fetchedAt ? new Date(data.fetchedAt) : new Date(),
            })
            .returning({ id: webIntelItems.id });

        itemId = inserted.id;
        log.info('Created new item', { itemId, url: data.url });
    }

    // 2. Persist IOC mentions
    let mentionsCreated = 0;
    if (data.iocs && typeof data.iocs === 'object') {
        const mentionRows: Array<{
            itemId: string;
            type: string;
            value: string;
            canonicalId: string;
            confidence: number;
        }> = [];

        for (const [iocType, values] of Object.entries(data.iocs)) {
            if (Array.isArray(values)) {
                for (const value of values) {
                    mentionRows.push({
                        itemId,
                        type: iocType,
                        value: String(value),
                        canonicalId: `${iocType}:${String(value).toLowerCase()}`,
                        confidence: 80,
                    });
                }
            }
        }

        if (mentionRows.length > 0) {
            for (const row of mentionRows) {
                try {
                    await db.insert(webIntelMentions).values(row);
                    mentionsCreated++;
                } catch (err) {
                    if (!(err as Error).message?.includes('duplicate')) {
                        log.warn('Mention insert failed', { error: (err as Error).message });
                    }
                }
            }
        }

        log.info('Created IOC mentions', { mentionsCreated, itemId });
    }

    // 3. Queue background processing (Neo4j sync + OpenSearch embedding)
    try {
        await nexusQueue.add(`persist-scrape-${itemId}`, {
            type: 'persist-scrape',
            itemId,
            url: data.url,
        }, {
            priority: 1,
        });
        log.info('Queued background processing', { itemId });
    } catch (err) {
        log.warn('Failed to queue background job', { error: (err as Error).message });
    }

    return { itemId, isNew, mentionsCreated };
}
