/**
 * Ops Enrichment Metrics Route
 *
 * Enrichment success rates, response times, and queue status.
 */

import { Hono } from 'hono';
import { enrichmentQueue } from '../../../../queues';
import { requireAuth } from '../../../../middleware/auth';

const router = new Hono();

/** GET /enrichment — Enrichment success rates, response times, and queue status */
router.get('/enrichment', requireAuth, async (c) => {
    const queueCounts = await enrichmentQueue.getJobCounts();
    const completedJobs = await enrichmentQueue.getCompleted(0, 100);
    const failedJobs = await enrichmentQueue.getFailed(0, 100);

    // Calculate success rate
    const totalRecent = completedJobs.length + failedJobs.length;
    const successRate = totalRecent > 0
        ? Math.round((completedJobs.length / totalRecent) * 100)
        : 100;

    // Calculate average processing time
    let avgProcessingTimeMs = 0;
    if (completedJobs.length > 0) {
        const processingTimes = completedJobs
            .filter(j => j.finishedOn && j.processedOn)
            .map(j => (j.finishedOn! - j.processedOn!));
        if (processingTimes.length > 0) {
            avgProcessingTimeMs = Math.round(
                processingTimes.reduce((a, b) => a + b, 0) / processingTimes.length
            );
        }
    }

    // Group failures by error type
    const errorBreakdown: Record<string, number> = {};
    for (const job of failedJobs.slice(0, 50)) {
        const errorType = job.failedReason?.split(':')[0] || 'Unknown';
        errorBreakdown[errorType] = (errorBreakdown[errorType] || 0) + 1;
    }

    // Recent failures (last 10)
    const recentErrors = failedJobs.slice(0, 10).map(j => ({
        jobId: j.id,
        iocValue: j.data?.iocValue || 'unknown',
        error: j.failedReason?.substring(0, 100) || 'Unknown error',
        timestamp: j.finishedOn ? new Date(j.finishedOn).toISOString() : null,
    }));

    return c.json({
        success: true,
        data: {
            queue: {
                waiting: queueCounts.waiting,
                active: queueCounts.active,
                completed: queueCounts.completed,
                failed: queueCounts.failed,
                delayed: queueCounts.delayed,
            },
            performance: {
                successRate,
                avgProcessingTimeMs,
                totalProcessed: queueCounts.completed + queueCounts.failed,
            },
            errorBreakdown,
            recentErrors,
            timestamp: new Date().toISOString(),
        },
    });
});

export default router;
