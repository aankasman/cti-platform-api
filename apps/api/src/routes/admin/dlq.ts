/**
 * Dead Letter Queue Admin Routes
 *
 * Provides inspection, replay, and cleanup for jobs that exhausted
 * all retry attempts across any queue.
 *
 * Mounts at: /admin/dlq/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { deadLetterQueue } from '../../queues/definitions';
import { AdminDLQListSchema } from '../../lib/schemas';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';

const log = createLogger('DLQ');
const router = new Hono();

// ============================================================================
// List Dead Letter entries
// ============================================================================

/** GET /dlq — List failed jobs (paginated) */
router.get('/dlq', requireAuth, requireRole('admin'), async (c) => {
    const { page, limit } = AdminDLQListSchema.parse(c.req.query());
    const start = (page - 1) * limit;

    const [waiting, counts] = await Promise.all([
        deadLetterQueue.getJobs(['waiting', 'completed', 'delayed'], start, start + limit - 1),
        deadLetterQueue.getJobCounts(),
    ]);

    const entries = waiting.map(job => ({
        id: job.id,
        originalQueue: job.data?.originalQueue,
        originalJobId: job.data?.originalJobId,
        failedReason: job.data?.failedReason,
        failedAt: job.data?.failedAt,
        data: job.data?.data,
        addedAt: job.timestamp ? new Date(job.timestamp).toISOString() : null,
    }));

    return c.json({
        success: true,
        data: {
            entries,
            total: counts.waiting + counts.completed + counts.delayed,
            page,
            limit,
            counts,
        },
    });
});

// ============================================================================
// DLQ Stats
// ============================================================================

/** GET /dlq/stats — Queue health summary */
router.get('/dlq/stats', requireAuth, requireRole('admin'), async (c) => {
    const counts = await deadLetterQueue.getJobCounts();

    return c.json({
        success: true,
        data: {
            counts,
            queueName: 'dead-letter',
            isPaused: await deadLetterQueue.isPaused(),
        },
    });
});

// ============================================================================
// Replay a Dead Letter entry
// ============================================================================

/** POST /dlq/:id/replay — Re-queue a dead letter job to its original queue */
router.post('/dlq/:id/replay', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const job = await deadLetterQueue.getJob(id);

    if (!job) {
        throw new NotFoundError('DLQ entry', id);
    }

    const { originalQueue, data } = job.data;

    if (!originalQueue) {
        throw new ValidationError('Missing originalQueue — cannot replay');
    }

    // Dynamically import the queue to add the job back
    const { Queue } = await import('bullmq');
    const { connection } = await import('../../services/redis');
    const targetQueue = new Queue(originalQueue, { connection });

    try {
        const newJob = await targetQueue.add('replay', data, {
            attempts: 3,
            backoff: { type: 'exponential', delay: 5000 },
        });

        // Remove from DLQ after successful replay
        await job.remove();

        log.info('DLQ entry replayed', {
            dlqJobId: id,
            originalQueue,
            newJobId: newJob.id,
        });

        return c.json({
            success: true,
            data: {
                replayed: true,
                originalQueue,
                newJobId: newJob.id,
            },
        });
    } finally {
        await targetQueue.close();
    }
});

// ============================================================================
// Delete a DLQ entry
// ============================================================================

/** DELETE /dlq/:id — Remove a dead letter entry */
router.delete('/dlq/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const job = await deadLetterQueue.getJob(id);

    if (!job) {
        throw new NotFoundError('DLQ entry', id);
    }

    await job.remove();
    log.info('DLQ entry removed', { jobId: id });

    return c.json({ success: true, data: { deleted: true } });
});

// ============================================================================
// Purge all DLQ entries
// ============================================================================

/** DELETE /dlq/purge — Purge all dead letter entries */
router.delete('/dlq/purge', requireAuth, requireRole('admin'), async (c) => {
    await deadLetterQueue.obliterate({ force: true });
    log.info('DLQ purged');

    return c.json({ success: true, data: { purged: true } });
});

export default router;
