/**
 * Web Search Routes (Queue-First Pattern)
 *
 * POST /v1/web-search        → Enqueue a web search job → returns { jobId }
 * GET  /v1/web-search/:jobId → Poll job status → returns result when complete
 *
 * Complements the existing synchronous /nexus/search route.
 * All requests are validated with Zod schemas shared between API and worker.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { randomUUID } from 'crypto';
import { Queue } from 'bullmq';
import { connection } from '../../../services/redis';
import { WebSearchRequestSchema } from '../../../lib/schemas';
import { ValidationError, NotFoundError } from '../../../lib/errors';
import { createLogger } from '../../../lib/logger';

const log = createLogger('WebSearchRoute');

const webSearch = new Hono();

// ============================================================================
// Queue (matches the queue name consumed by webSearchWorker.ts)
// ============================================================================

const webSearchQueue = new Queue('web-search', {
    connection,
    defaultJobOptions: {
        attempts: 3,
        backoff: {
            type: 'exponential',
            delay: 5000,
        },
        removeOnComplete: { count: 500 },
        removeOnFail: { count: 1000 },
    },
});

// ============================================================================
// POST /v1/web-search — Enqueue a web search job
// ============================================================================

webSearch.post('/', async (c: Context) => {
    const correlationId = randomUUID();
    const body = await c.req.json();

    // Validate with Zod
    const parsed = WebSearchRequestSchema.safeParse(body);
    if (!parsed.success) {
        const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
        throw new ValidationError(`Invalid request: ${issues.join('; ')}`);
    }

    const jobData = {
        ...parsed.data,
        correlationId,
        createdAt: new Date().toISOString(),
    };

    const job = await webSearchQueue.add(`search-${correlationId}`, jobData, {
        priority: parsed.data.persist ? 3 : 5, // Persistence jobs get higher priority
    });

    log.info('Job enqueued', { jobId: job.id, correlationId, query: parsed.data.query });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            correlationId,
            status: 'queued',
            message: `Web search job queued. Poll GET /v1/web-search/${job.id} for results.`,
        },
    }, 202);
});

// ============================================================================
// GET /v1/web-search/:jobId — Poll job status
// ============================================================================

webSearch.get('/:jobId', async (c: Context) => {
    const jobId = c.req.param('jobId');
    const job = await webSearchQueue.getJob(jobId);

    if (!job) {
        throw new NotFoundError('Job', jobId);
    }

    const state = await job.getState();
    const progress = job.progress;

    const response: Record<string, unknown> = {
        jobId: job.id,
        status: state,
        progress: typeof progress === 'number' ? progress : 0,
        createdAt: job.data?.createdAt,
    };

    if (state === 'completed') {
        response.result = job.returnvalue;
        response.completedAt = job.finishedOn
            ? new Date(job.finishedOn).toISOString()
            : undefined;
    }

    if (state === 'failed') {
        response.error = job.failedReason;
        response.attemptsMade = job.attemptsMade;
    }

    return c.json({ success: true, data: response });
});

export default webSearch;
