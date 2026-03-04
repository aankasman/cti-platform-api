import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { getFeedHandler, getRegisteredFeeds } from '../../services/feedSync/feedRegistry';
import type { FeedSyncJobData } from '../types';
import { enrichmentQueue } from '../definitions';
import { createLogger } from '../../lib/logger';
import { getConfig, getFeedById } from '../../services/configStore';

const AUTO_ENRICH_CONFIG = {
    enabled: process.env.AUTO_ENRICH_ENABLED === 'true', // opt-IN: set AUTO_ENRICH_ENABLED=true to enable
    batchSize: parseInt(process.env.AUTO_ENRICH_BATCH_SIZE || '50', 10),
    priorityTypes: ['ip', 'domain', 'hash', 'url'],
    delayMs: 500,
};

export const feedSyncWorker = new Worker<FeedSyncJobData>(
    'feed-sync',
    async (job: Job<FeedSyncJobData>) => {
        const log = createLogger('FeedSync');

        // Check if feed sync is disabled via dashboard toggle
        const enabled = await getConfig('FEED_SYNC_ENABLED');
        if (enabled === 'false') {
            log.info('Feed sync disabled via settings, skipping', { jobId: job.id, source: job.data.source });
            return { skipped: true, reason: 'Feed sync disabled via settings' };
        }

        log.info('Processing job', { jobId: job.id, source: job.data.source });

        const { source, options } = job.data;
        let result;
        const newIOCs: Array<{ id: string; value: string; type: string }> = [];

        try {
            await job.updateProgress(10);

            if (source === 'all') {
                // Run all registered feeds
                const sources = getRegisteredFeeds();
                log.info('Syncing all feeds', { feedCount: sources.length, feeds: sources });
                const results = await Promise.allSettled(
                    sources.map(async (s) => {
                        log.info(`[all] Starting feed: ${s}`);
                        const handler = getFeedHandler(s)!;
                        const res = await handler(options);
                        log.info(`[all] Completed feed: ${s}`, {
                            added: res.indicatorsAdded,
                            processed: res.indicatorsProcessed,
                            success: res.success,
                        });
                        return { source: s, result: res };
                    })
                );

                let totalAdded = 0;
                let totalProcessed = 0;
                let succeeded = 0;
                let failed = 0;
                const perFeed: Record<string, unknown> = {};
                for (const r of results) {
                    if (r.status === 'fulfilled') {
                        const { source: src, result: res } = r.value;
                        perFeed[src] = res;
                        totalAdded += res.indicatorsAdded;
                        totalProcessed += res.indicatorsProcessed || 0;
                        succeeded++;
                        if (res.indicators && res.indicators.length > 0) {
                            newIOCs.push(...res.indicators);
                        }
                    } else {
                        failed++;
                        log.error(`[all] Feed failed`, new Error(r.reason?.message || String(r.reason)));
                    }
                }
                log.info('All feeds sync summary', {
                    succeeded, failed, totalAdded, totalProcessed,
                });
                result = {
                    ...perFeed,
                    indicatorsAdded: totalAdded,
                    indicatorsProcessed: totalProcessed,
                };
            } else {
                // Check if specific feed is enabled in DB
                const feedConfig = await getFeedById(source);
                if (feedConfig && !feedConfig.enabled) {
                    log.warn(`Feed '${source}' is disabled — skipping job`, {
                        jobId: job.id, feedId: feedConfig.id, source,
                    });
                    return { skipped: true, reason: `Feed '${source}' is disabled` };
                }

                const handler = getFeedHandler(source);
                if (!handler) {
                    log.error(`Unknown feed source: ${source}`, new Error(`No handler registered for '${source}'`), {
                        jobId: job.id, registeredFeeds: getRegisteredFeeds(),
                    });
                    throw new Error(`Unknown feed source: ${source}`);
                }

                log.info(`Dispatching feed sync: ${source}`, {
                    jobId: job.id, hasConfig: !!feedConfig, options,
                });
                result = await handler(options);
                log.info(`Feed sync completed: ${source}`, {
                    jobId: job.id, success: result.success,
                    added: result.indicatorsAdded, processed: result.indicatorsProcessed,
                    errors: result.errors?.length || 0,
                });
                if (result.indicators && result.indicators.length > 0) {
                    newIOCs.push(...result.indicators);
                }
            }

            await job.updateProgress(70);

            // Auto-enrichment
            let enrichmentJobsQueued = 0;
            if (AUTO_ENRICH_CONFIG.enabled && newIOCs.length > 0) {
                log.info('Auto-enrichment enabled', { queueing: Math.min(newIOCs.length, AUTO_ENRICH_CONFIG.batchSize) });

                const iocsToEnrich = newIOCs
                    .filter(ioc => AUTO_ENRICH_CONFIG.priorityTypes.includes(ioc.type))
                    .slice(0, AUTO_ENRICH_CONFIG.batchSize);

                for (let i = 0; i < iocsToEnrich.length; i++) {
                    const ioc = iocsToEnrich[i];
                    await enrichmentQueue.add(
                        `auto-enrich-${ioc.id}`,
                        {
                            iocId: ioc.id,
                            iocValue: ioc.value,
                            iocType: ioc.type,
                            sources: ['virustotal', 'geoip'],
                        },
                        {
                            delay: i * AUTO_ENRICH_CONFIG.delayMs,
                            priority: 5,
                        }
                    );
                    enrichmentJobsQueued++;
                }
                log.info('Auto-enrichment jobs queued', { count: enrichmentJobsQueued });
            }

            await job.updateProgress(100);

            const { success: _, ...syncData } = (result || {}) as Record<string, unknown>;

            return {
                success: true,
                source,
                processedAt: new Date().toISOString(),
                autoEnrichmentJobsQueued: enrichmentJobsQueued,
                ...syncData,
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            await job.updateData({
                ...job.data,
                _errorMeta: {
                    message: (error as Error).message,
                    stack: (error as Error).stack?.split('\n').slice(0, 5).join('\n'),
                    attemptsMade: job.attemptsMade + 1,
                    failedAt: new Date().toISOString(),
                },
            } as FeedSyncJobData & { _errorMeta: { message: string; stack?: string; attemptsMade: number; failedAt: string } });
            throw error;
        }
    },
    {
        connection,
        concurrency: 2,
    }
);
