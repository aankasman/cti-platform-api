/**
 * Ops Worker Performance Metrics Route
 *
 * Worker throughput, processing times, and queue depths.
 */

import { Hono } from 'hono';
import {
    feedSyncQueue,
    enrichmentQueue,
    aiAnalysisQueue,
    notificationQueue,
    alertsQueue,
} from '../../queues';
import { requireAuth } from '../../middleware/auth';

const router = new Hono();

/** GET /workers — Worker throughput, processing times, and queue depths */
router.get('/workers', requireAuth, async (c) => {
    const queues = [
        { name: 'feed-sync', queue: feedSyncQueue },
        { name: 'ioc-enrichment', queue: enrichmentQueue },
        { name: 'ai-analysis', queue: aiAnalysisQueue },
        { name: 'notifications', queue: notificationQueue },
        { name: 'alerts', queue: alertsQueue },
    ];

    const workerMetrics = await Promise.all(
        queues.map(async ({ name, queue }) => {
            const counts = await queue.getJobCounts();
            const completed = await queue.getCompleted(0, 50);
            const failed = await queue.getFailed(0, 20);

            // Calculate throughput (jobs completed in last hour)
            const oneHourAgo = Date.now() - 60 * 60 * 1000;
            const recentCompleted = completed.filter(j => j.finishedOn && j.finishedOn > oneHourAgo);
            const throughputPerHour = recentCompleted.length;

            // Calculate average processing time
            let avgProcessingTimeMs = 0;
            const processingTimes = completed
                .filter(j => j.finishedOn && j.processedOn)
                .map(j => j.finishedOn! - j.processedOn!);
            if (processingTimes.length > 0) {
                avgProcessingTimeMs = Math.round(
                    processingTimes.reduce((a, b) => a + b, 0) / processingTimes.length
                );
            }

            // Error rate
            const total = counts.completed + counts.failed;
            const errorRate = total > 0 ? Math.round((counts.failed / total) * 100) : 0;

            return {
                name,
                counts: {
                    waiting: counts.waiting,
                    active: counts.active,
                    completed: counts.completed,
                    failed: counts.failed,
                    delayed: counts.delayed,
                },
                performance: {
                    throughputPerHour,
                    avgProcessingTimeMs,
                    errorRate,
                },
                recentFailures: failed.slice(0, 5).map(j => ({
                    jobId: j.id,
                    error: j.failedReason?.substring(0, 80) || 'Unknown',
                    timestamp: j.finishedOn ? new Date(j.finishedOn).toISOString() : null,
                })),
            };
        })
    );

    // Overall stats
    const totalActive = workerMetrics.reduce((sum, w) => sum + w.counts.active, 0);
    const totalWaiting = workerMetrics.reduce((sum, w) => sum + w.counts.waiting, 0);
    const totalThroughput = workerMetrics.reduce((sum, w) => sum + w.performance.throughputPerHour, 0);

    return c.json({
        success: true,
        data: {
            summary: {
                totalActive,
                totalWaiting,
                totalThroughputPerHour: totalThroughput,
            },
            workers: workerMetrics,
            timestamp: new Date().toISOString(),
        },
    });
});

export default router;
