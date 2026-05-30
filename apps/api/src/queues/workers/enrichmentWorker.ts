/**
 * IOC Enrichment Worker
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { enrichIOC } from '@rinjani/core/enrichment';
import type { EnrichmentSource } from '@rinjani/core/enrichment';
import type { EnrichmentJobData } from '../types';
import { createLogger } from '../../lib/logger';
import { getConfig } from '../../services/configStore';

export const enrichmentWorker = new Worker<EnrichmentJobData>(
    'ioc-enrichment',
    async (job: Job<EnrichmentJobData>) => {
        const log = createLogger('Enrichment');

        // Check if enrichment is disabled via dashboard toggle
        const enabled = await getConfig('ENRICHMENT_ENABLED');
        if (enabled === 'false') {
            log.info('Enrichment disabled via settings, skipping', { jobId: job.id, iocValue: job.data.iocValue });
            return { skipped: true, reason: 'Enrichment disabled via settings' };
        }

        log.info('Processing job', { jobId: job.id, iocValue: job.data.iocValue });

        const { iocId, iocValue, iocType, sources } = job.data;

        try {
            await job.updateProgress(10);

            const enrichmentSources = (sources || ['virustotal', 'geoip']) as EnrichmentSource[];

            log.info('Enriching IOC', { iocType, iocValue, sources: enrichmentSources });
            await job.updateProgress(30);

            const enrichedData = await enrichIOC(iocValue, {
                sources: enrichmentSources,
                priority: 'comprehensive',
            });

            await job.updateProgress(70);

            // Write enrichment results back to PostgreSQL
            // NOTE: Match by iocValue (not iocId) because feed syncs may use
            // composite IDs (e.g. "otx-{pulseId}-{indicatorId}") that aren't
            // valid UUIDs, whereas iocs.value is the canonical lookup key.
            try {
                const { iocs: iocsTable } = await import('@rinjani/db/schema');
                const { db: dbConn, eq: eqOp } = await import('@rinjani/db');

                await dbConn.update(iocsTable)
                    .set({
                        severity: enrichedData.riskLevel || undefined,
                        confidence: enrichedData.overallScore ? Math.round(enrichedData.overallScore) : undefined,
                        tags: enrichedData.tags?.length > 0 ? enrichedData.tags : undefined,
                        lastSeen: new Date(),
                        updatedAt: new Date(),
                    })
                    .where(eqOp(iocsTable.value, iocValue));

                log.info('Updated IOC in PostgreSQL', { iocValue, severity: enrichedData.riskLevel, score: enrichedData.overallScore });
            } catch (dbErr) {
                log.warn('Failed to update IOC in DB (non-fatal)', { iocValue, error: (dbErr as Error).message });
            }

            await job.updateProgress(100);

            return {
                success: true,
                iocId,
                enrichedAt: new Date().toISOString(),
                sources: enrichmentSources,
                riskLevel: enrichedData.riskLevel,
                riskScore: enrichedData.overallScore,
                tags: enrichedData.tags,
                enrichmentCount: enrichedData.enrichments.length,
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
            } as EnrichmentJobData & { _errorMeta: { message: string; stack?: string; attemptsMade: number; failedAt: string } });
            throw error;
        }
    },
    {
        connection,
        // Default rate limit matches VirusTotal's free-tier quota
        // (4 requests / minute / API key). Each IOC enrichment makes
        // exactly one VT call (see packages/core/src/enrichment.ts —
        // one fetch per IOC, routed by type to ip_addresses / domains
        // / urls / files), so 4 jobs/min ≈ 4 VT calls/min, the cap.
        //
        // Concurrency matches the limit because BullMQ will block
        // additional jobs once the limit hits anyway — running more
        // than `max` in parallel buys nothing under a tight limiter,
        // it just queues them and immediately stalls.
        //
        // Override via env when you have a paid VT key:
        //   ENRICHMENT_RATE_LIMIT_PER_MIN=300   (VT Premium tier)
        //   ENRICHMENT_CONCURRENCY=8            (independent of limit)
        //
        // Leaving these unset is the safe-for-new-installs default —
        // turning AUTO_ENRICH_ENABLED on with the stock limits won't
        // burn the free quota even if a feed-sync fans 50 children.
        concurrency: Number(process.env.ENRICHMENT_CONCURRENCY)
            || Math.min(4, Number(process.env.ENRICHMENT_RATE_LIMIT_PER_MIN) || 4),
        limiter: {
            max: Number(process.env.ENRICHMENT_RATE_LIMIT_PER_MIN) || 4,
            duration: 60_000,
        },
    }
);
