/**
 * Background Job Processor
 * 
 * Handles async processing of enrichment, webhook delivery, and other background tasks.
 * Uses an in-memory queue (replace with Redis/BullMQ in production).
 */

// ============================================================================
// Types
// ============================================================================

export type JobType = 'enrichment' | 'webhook_delivery' | 'sync' | 'export' | 'cleanup';
export type JobStatus = 'pending' | 'processing' | 'completed' | 'failed' | 'retrying';

export interface Job<T = unknown> {
    id: string;
    type: JobType;
    payload: T;
    status: JobStatus;
    attempts: number;
    maxAttempts: number;
    priority: number;
    result?: unknown;
    error?: string;
    createdAt: Date;
    startedAt?: Date;
    completedAt?: Date;
    scheduledFor?: Date;
}

export interface JobHandler<T = unknown> {
    (job: Job<T>): Promise<unknown>;
}

// ============================================================================
// Job Queue
// ============================================================================

const jobQueue: Job[] = [];
const jobHandlers = new Map<JobType, JobHandler>();
let isProcessing = false;
let processingInterval: ReturnType<typeof setInterval> | null = null;

// ============================================================================
// Queue Operations
// ============================================================================

/**
 * Add a job to the queue
 */
export function enqueueJob<T>(
    type: JobType,
    payload: T,
    options: {
        priority?: number;
        maxAttempts?: number;
        delay?: number;
    } = {}
): Job<T> {
    const job: Job<T> = {
        id: crypto.randomUUID(),
        type,
        payload,
        status: 'pending',
        attempts: 0,
        maxAttempts: options.maxAttempts || 3,
        priority: options.priority || 0,
        createdAt: new Date(),
        scheduledFor: options.delay
            ? new Date(Date.now() + options.delay)
            : undefined,
    };

    jobQueue.push(job);

    // Sort by priority (higher first) and creation time
    jobQueue.sort((a, b) => {
        if (a.priority !== b.priority) return b.priority - a.priority;
        return a.createdAt.getTime() - b.createdAt.getTime();
    });

    return job;
}

/**
 * Get job by ID
 */
export function getJob(id: string): Job | undefined {
    return jobQueue.find(j => j.id === id);
}

/**
 * Get queue statistics
 */
export function getQueueStats(): {
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    retrying: number;
    byType: Record<JobType, number>;
} {
    const stats = {
        pending: 0,
        processing: 0,
        completed: 0,
        failed: 0,
        retrying: 0,
        byType: {} as Record<JobType, number>,
    };

    for (const job of jobQueue) {
        stats[job.status]++;
        stats.byType[job.type] = (stats.byType[job.type] || 0) + 1;
    }

    return stats;
}

/**
 * Register a job handler
 */
export function registerJobHandler<T>(type: JobType, handler: JobHandler<T>): void {
    jobHandlers.set(type, handler as JobHandler);
}

// ============================================================================
// Processing
// ============================================================================

async function processNextJob(): Promise<void> {
    if (isProcessing) return;

    // Find next pending job that's ready to process
    const now = new Date();
    const jobIndex = jobQueue.findIndex(
        j => j.status === 'pending' && (!j.scheduledFor || j.scheduledFor <= now)
    );

    if (jobIndex === -1) return;

    const job = jobQueue[jobIndex];
    const handler = jobHandlers.get(job.type);

    if (!handler) {
        job.status = 'failed';
        job.error = `No handler registered for job type: ${job.type}`;
        return;
    }

    isProcessing = true;
    job.status = 'processing';
    job.startedAt = new Date();
    job.attempts++;

    try {
        job.result = await handler(job);
        job.status = 'completed';
        job.completedAt = new Date();
    } catch (err: any) {
        job.error = err.message;

        if (job.attempts < job.maxAttempts) {
            job.status = 'retrying';
            // Exponential backoff
            job.scheduledFor = new Date(Date.now() + Math.pow(2, job.attempts) * 1000);
            job.status = 'pending';
        } else {
            job.status = 'failed';
        }
    } finally {
        isProcessing = false;
    }
}

/**
 * Start the job processor
 */
export function startJobProcessor(intervalMs: number = 1000): void {
    if (processingInterval) return;

    processingInterval = setInterval(processNextJob, intervalMs);
    console.log('[Jobs] Background job processor started');
}

/**
 * Stop the job processor
 */
export function stopJobProcessor(): void {
    if (processingInterval) {
        clearInterval(processingInterval);
        processingInterval = null;
        console.log('[Jobs] Background job processor stopped');
    }
}

// ============================================================================
// Built-in Job Handlers
// ============================================================================

// Enrichment job handler
registerJobHandler<{ value: string; sources: string[] }>('enrichment', async (job) => {
    const { value, sources } = job.payload;

    // In production, this would call the enrichment service
    console.log(`[Jobs] Processing enrichment for ${value} with sources: ${sources.join(', ')}`);

    // Simulate enrichment
    await new Promise(resolve => setTimeout(resolve, 500));

    return {
        value,
        enriched: true,
        sources,
        timestamp: new Date().toISOString(),
    };
});

// Cleanup job handler
registerJobHandler<{ olderThan: number }>('cleanup', async (job) => {
    const { olderThan } = job.payload;
    const cutoff = new Date(Date.now() - olderThan);

    // Remove completed/failed jobs older than cutoff
    const initialLength = jobQueue.length;
    const toRemove = jobQueue.filter(
        j => (j.status === 'completed' || j.status === 'failed') && j.createdAt < cutoff
    );

    for (const job of toRemove) {
        const idx = jobQueue.indexOf(job);
        if (idx !== -1) jobQueue.splice(idx, 1);
    }

    return {
        removed: initialLength - jobQueue.length,
        remaining: jobQueue.length,
    };
});
