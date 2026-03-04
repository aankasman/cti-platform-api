/**
 * Nexus Intelligence Worker
 *
 * Processes webhook items, webset syncs, and persist-scrape jobs.
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { db, eq, sql } from '@rinjani/db';
import { exaWebsets, webIntelItems, webIntelMentions } from '@rinjani/db/schema';
import type { NexusJobData } from '../types';
import { nexusQueue } from '../definitions';
import { extractIOCsFromMultiple } from '../../services/iocExtractor';
import * as exaService from '../../services/exa';
import { wsManager } from '../../websocket';
import { processPostSave } from '../../services/webIntelPersist';
import { createLogger } from '../../lib/logger';

export const nexusWorker = new Worker<NexusJobData>(
    'nexus-intel',
    async (job: Job<NexusJobData>) => {
        const log = createLogger('Nexus');
        log.info('Processing job', { jobId: job.id, type: job.data.type });

        try {
            switch (job.data.type) {
                case 'webhook-item': {
                    const item = job.data.payload as Record<string, unknown> & {
                        id?: string; websetId?: string; title?: string; url?: string;
                        sourceUrl?: string; contents?: { text?: string };
                        enrichmentResults?: Record<string, unknown>;
                    };
                    if (!item?.id || !item?.websetId) {
                        throw new Error('Invalid webhook item payload');
                    }

                    await job.updateProgress(10);

                    const [localWebset] = await db.select().from(exaWebsets)
                        .where(eq(exaWebsets.exaWebsetId, item.websetId));

                    if (!localWebset) {
                        log.info('Webset not tracked locally, skipping', { websetId: item.websetId });
                        return { success: true, skipped: true };
                    }

                    await job.updateProgress(30);

                    const textContent = item.contents?.text || '';
                    const title = item.title || item.url || '';

                    const [inserted] = await db.insert(webIntelItems).values({
                        exaItemId: item.id,
                        websetId: localWebset.id,
                        category: localWebset.category,
                        title,
                        url: item.url,
                        sourceUrl: item.sourceUrl || item.url,
                        textContent,
                        enrichments: item.enrichmentResults || {},
                        iocExtracted: false,
                    }).onConflictDoNothing().returning();

                    await job.updateProgress(60);

                    if (inserted) {
                        const extraction = extractIOCsFromMultiple([title, textContent]);
                        if (extraction.iocs.length > 0) {
                            await db.insert(webIntelMentions).values(
                                extraction.iocs.map(ioc => ({
                                    itemId: inserted.id,
                                    type: ioc.type,
                                    value: ioc.value,
                                    canonicalId: ioc.canonicalId,
                                    confidence: ioc.confidence,
                                    context: ioc.context || null,
                                }))
                            );
                        }

                        await db.update(webIntelItems)
                            .set({ iocExtracted: true, updatedAt: new Date() })
                            .where(eq(webIntelItems.id, inserted.id));

                        wsManager.broadcast('webint', {
                            type: 'ioc',
                            data: {
                                event: 'nexus-item',
                                itemId: inserted.id,
                                category: localWebset.category,
                                title,
                                url: item.url,
                                iocsFound: extraction.iocs.length,
                                iocTypes: extraction.stats,
                            },
                        });

                        if (localWebset.category === 'socmint') {
                            wsManager.broadcast('socmint', {
                                type: 'ioc',
                                data: {
                                    event: 'social-intel',
                                    title,
                                    url: item.url,
                                    iocsFound: extraction.iocs.length,
                                },
                            });
                        }

                        await job.updateProgress(100);
                        return {
                            success: true,
                            itemId: inserted.id,
                            iocsExtracted: extraction.iocs.length,
                            category: localWebset.category,
                        };
                    }

                    return { success: true, skipped: true, reason: 'duplicate' };
                }

                case 'sync-webset': {
                    const websetId = job.data.websetId;
                    if (!websetId) throw new Error('websetId required');

                    await job.updateProgress(5);

                    const [localWebset] = await db.select().from(exaWebsets)
                        .where(eq(exaWebsets.exaWebsetId, websetId));

                    if (!localWebset) {
                        throw new Error(`Webset ${websetId} not tracked locally`);
                    }

                    let cursor: string | undefined;
                    let totalSynced = 0;
                    let totalIOCs = 0;
                    let pageCount = 0;

                    do {
                        const page = await exaService.listWebsetItems(websetId, { limit: 50, cursor });
                        const items = page.data || [];

                        for (const item of items) {
                            const textContent = item.contents?.text || item.contents?.summary || '';
                            const title = item.title || item.url || '';

                            const [inserted] = await db.insert(webIntelItems).values({
                                exaItemId: item.id,
                                websetId: localWebset.id,
                                category: localWebset.category,
                                title,
                                url: item.url,
                                sourceUrl: item.sourceUrl || item.url,
                                textContent,
                                summary: item.contents?.summary || null,
                                highlights: item.contents?.highlights || [],
                                enrichments: item.enrichmentResults || {},
                                publishedAt: item.publishedDate ? new Date(item.publishedDate) : null,
                                iocExtracted: false,
                                embeddingGenerated: false,
                                neo4jSynced: false,
                            }).onConflictDoNothing().returning();

                            if (inserted) {
                                const extraction = extractIOCsFromMultiple([title, textContent]);
                                if (extraction.iocs.length > 0) {
                                    await db.insert(webIntelMentions).values(
                                        extraction.iocs.map(ioc => ({
                                            itemId: inserted.id,
                                            type: ioc.type,
                                            value: ioc.value,
                                            canonicalId: ioc.canonicalId,
                                            confidence: ioc.confidence,
                                            context: ioc.context || null,
                                        }))
                                    );
                                    totalIOCs += extraction.iocs.length;
                                }

                                await db.update(webIntelItems)
                                    .set({ iocExtracted: true, updatedAt: new Date() })
                                    .where(eq(webIntelItems.id, inserted.id));

                                totalSynced++;
                            }
                        }

                        pageCount++;
                        cursor = page.hasMore ? page.cursor : undefined;
                        await job.updateProgress(Math.min(90, 5 + pageCount * 10));
                    } while (cursor);

                    const [countResult] = await db.select({
                        total: sql<number>`count(*)::int`,
                    }).from(webIntelItems)
                        .where(eq(webIntelItems.websetId, localWebset.id));

                    await db.update(exaWebsets)
                        .set({ itemCount: countResult?.total || totalSynced, lastSyncAt: new Date(), updatedAt: new Date() })
                        .where(eq(exaWebsets.id, localWebset.id));

                    wsManager.broadcast('webint', {
                        type: 'sync',
                        data: {
                            event: 'nexus-sync-complete',
                            websetId,
                            category: localWebset.category,
                            itemsSynced: totalSynced,
                            iocsExtracted: totalIOCs,
                        },
                    });

                    await job.updateProgress(100);
                    return {
                        success: true,
                        websetId,
                        itemsSynced: totalSynced,
                        iocsExtracted: totalIOCs,
                    };
                }

                case 'sync-all-websets': {
                    const allWebsets = await db.select().from(exaWebsets);
                    await job.updateProgress(10);

                    let queued = 0;
                    for (const ws of allWebsets) {
                        await nexusQueue.add(`scheduled-sync-${ws.exaWebsetId}`, {
                            type: 'sync-webset',
                            websetId: ws.exaWebsetId,
                            category: ws.category,
                        }, {
                            delay: queued * 2000,
                        });
                        queued++;
                    }

                    await job.updateProgress(100);
                    return {
                        success: true,
                        websetsQueued: queued,
                        categories: allWebsets.map(w => w.category),
                    };
                }

                case 'persist-scrape': {
                    const persistItemId = job.data.itemId as string;
                    if (!persistItemId) throw new Error('itemId required for persist-scrape');

                    await job.updateProgress(10);
                    await processPostSave(persistItemId);
                    await job.updateProgress(100);

                    return {
                        success: true,
                        type: 'persist-scrape',
                        itemId: persistItemId,
                    };
                }

                case 'batch-scrape': {
                    const urls = job.data.urls || [];
                    if (urls.length === 0) {
                        return { success: true, type: 'batch-scrape', scraped: 0, skipped: 0 };
                    }

                    const { scrapeAndExtract } = await import('../../services/searxng');
                    const { saveScrapeResult } = await import('../../services/webIntelPersist');

                    let scraped = 0;
                    let skipped = 0;
                    let failed = 0;

                    for (let i = 0; i < urls.length; i++) {
                        const url = urls[i];
                        try {
                            // Check if already scraped (dedup)
                            const existing = await db.select({ id: webIntelItems.id })
                                .from(webIntelItems)
                                .where(eq(webIntelItems.url, url))
                                .limit(1);

                            if (existing.length > 0) {
                                skipped++;
                                continue;
                            }

                            const result = await scrapeAndExtract(url);

                            // Group IOCs by type for persistence format
                            const iocsByType: Record<string, string[]> = {};
                            if (Array.isArray(result.iocs)) {
                                for (const ioc of result.iocs) {
                                    if (!iocsByType[ioc.type]) iocsByType[ioc.type] = [];
                                    iocsByType[ioc.type].push(ioc.value);
                                }
                            }

                            await saveScrapeResult({
                                url,
                                title: result.title,
                                text: result.text,
                                iocs: iocsByType,
                                iocStats: result.iocStats?.byType,
                                fetchedAt: result.fetchedAt,
                            });
                            scraped++;
                        } catch (err) {
                            failed++;
                            log.warn('Batch scrape: URL failed (non-blocking)', {
                                url,
                                error: (err as Error).message,
                            });
                        }

                        await job.updateProgress(Math.round(((i + 1) / urls.length) * 100));
                    }

                    log.info('Batch scrape complete', {
                        total: urls.length,
                        scraped,
                        skipped,
                        failed,
                        query: job.data.query,
                    });

                    return {
                        success: true,
                        type: 'batch-scrape',
                        scraped,
                        skipped,
                        failed,
                        total: urls.length,
                    };
                }

                default:
                    throw new Error(`Unknown nexus job type: ${job.data.type}`);
            }
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    },
    {
        connection,
        concurrency: 3,
    }
);
