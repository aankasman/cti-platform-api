/**
 * Admin Job Trigger Routes
 *
 * Endpoints to manually queue feed-sync, enrichment, AI analysis,
 * notification, and Neo4j sync jobs.
 */

import { Hono } from 'hono';
import {
    feedSyncQueue,
    enrichmentQueue,
    aiAnalysisQueue,
    notificationQueue,
    neo4jSyncQueue,
    type FeedSyncJobData,
    type NotificationJobData,
    type Neo4jSyncJobData,
} from '../../../../queues';
import { requireAuth, requireRole } from '../../../../middleware/auth';
import { NotFoundError } from '../../../../lib/errors';
import {
    FeedSyncJobSchema, EnrichmentJobSchema, AiAnalysisJobSchema,
    NotificationJobQueueSchema, Neo4jSyncJobSchema,
} from '../../../../lib/schemas';

const router = new Hono();

/** POST /jobs/feed-sync — Trigger a feed sync job */
router.post('/jobs/feed-sync', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = FeedSyncJobSchema.parse(await c.req.json());
    const { source, options } = body;

    const job = await feedSyncQueue.add(`sync-${source}`, { source, options });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            queue: 'feed-sync',
            source,
            status: 'queued',
        },
    });
});

/** POST /jobs/enrichment — Queue IOC enrichment job */
router.post('/jobs/enrichment', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = EnrichmentJobSchema.parse(await c.req.json());
    const { iocId, iocValue, iocType, sources } = body;

    const job = await enrichmentQueue.add(`enrich-${iocId}`, {
        iocId,
        iocValue,
        iocType,
        sources,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            queue: 'ioc-enrichment',
            iocId,
            status: 'queued',
        },
    });
});

/** POST /jobs/ai-analysis — Queue AI analysis job */
router.post('/jobs/ai-analysis', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = AiAnalysisJobSchema.parse(await c.req.json());
    const { iocId, iocValue, analysisType } = body;

    const job = await aiAnalysisQueue.add(`analyze-${iocId}`, {
        iocId,
        iocValue,
        analysisType,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            queue: 'ai-analysis',
            iocId,
            analysisType,
            status: 'queued',
        },
    });
});

/** POST /jobs/notification — Queue a notification job */
router.post('/jobs/notification', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = NotificationJobQueueSchema.parse(await c.req.json());
    const { channel, target, payload } = body;

    const job = await notificationQueue.add(`notify-${channel}`, {
        channel,
        target,
        payload,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            queue: 'notifications',
            channel,
            target,
            status: 'queued',
        },
    });
});

/** POST /jobs/neo4j-sync — Trigger Postgres → Neo4j sync job */
router.post('/jobs/neo4j-sync', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = Neo4jSyncJobSchema.parse(await c.req.json());
    const { syncType, options } = body;

    const job = await neo4jSyncQueue.add(`neo4j-sync-${syncType}`, {
        syncType,
        options,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            queue: 'neo4j-sync',
            syncType,
            status: 'queued',
        },
    });
});

/** POST /jobs/cvss-backfill — Backfill missing CVSS scores from NVD (runs in background) */
router.post('/jobs/cvss-backfill', requireAuth, requireRole('admin'), async (c) => {
    const { backfillMissingCvss } = await import('../../../../services/feedSync/nvdSync');
    // Fire and forget — NVD rate limits make this take minutes
    backfillMissingCvss().catch(() => { });
    return c.json({ success: true, data: { status: 'running', message: 'CVSS backfill started in background. Check server logs for progress.' } });
});

/** POST /jobs/nvd-sync — Run NVD CVE sync directly (bypasses BullMQ worker) */
router.post('/jobs/nvd-sync', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { syncNVDFeed } = await import('../../../../services/feedSync/nvdSync');
    const result = await syncNVDFeed();
    return c.json({
        success: result.success,
        data: {
            status: 'completed',
            cves: result.indicatorsAdded,
            processed: result.indicatorsProcessed,
            errors: result.errors,
        },
    });
});

/** GET /jobs/:queue/:jobId — Get job status */
router.get('/jobs/:queue/:jobId', requireAuth, async (c) => {
    const { queue: queueName, jobId } = c.req.param();

    const queueMap: Record<string, typeof feedSyncQueue> = {
        'feed-sync': feedSyncQueue,
        'ioc-enrichment': enrichmentQueue,
        'ai-analysis': aiAnalysisQueue,
        'notifications': notificationQueue,
        'neo4j-sync': neo4jSyncQueue,
    };

    const queue = queueMap[queueName];
    if (!queue) {
        throw new NotFoundError('Queue', queueName);
    }

    const job = await queue.getJob(jobId);
    if (!job) {
        throw new NotFoundError('Job', jobId);
    }

    const state = await job.getState();
    const progress = job.progress;

    return c.json({
        success: true,
        data: {
            id: job.id,
            name: job.name,
            queue: queueName,
            state,
            progress,
            data: job.data,
            result: job.returnvalue,
            failedReason: job.failedReason,
            attemptsMade: job.attemptsMade,
            timestamp: job.timestamp,
            processedOn: job.processedOn,
            finishedOn: job.finishedOn,
        },
    });
});

export default router;
