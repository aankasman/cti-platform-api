/**
 * Worker Scheduler
 * 
 * Cron-like job scheduling for feed synchronization.
 * Supports:
 * - Cron expressions
 * - Interval-based scheduling
 * - Dynamic job registration from DB
 */

import { EventEmitter } from 'events';

// ============================================================================
// Types
// ============================================================================

export interface ScheduledJob {
    id: string;
    name: string;
    schedule: string;           // Cron expression or interval like "30m", "6h", "1d"
    handler: () => Promise<void>;
    enabled: boolean;
    lastRun?: Date;
    nextRun?: Date;
    runCount: number;
    failCount: number;
    metadata?: Record<string, unknown>;
}

export interface SchedulerConfig {
    timezone?: string;
    maxConcurrent?: number;
    defaultRetries?: number;
    onJobStart?: (job: ScheduledJob) => void;
    onJobComplete?: (job: ScheduledJob, duration: number) => void;
    onJobError?: (job: ScheduledJob, error: Error) => void;
}

// ============================================================================
// Interval Parser
// ============================================================================

function parseInterval(schedule: string): number {
    const match = schedule.match(/^(\d+)(s|m|h|d|w)$/);
    if (!match) {
        throw new Error(`Invalid interval format: ${schedule}. Use format like "30m", "6h", "1d"`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers: Record<string, number> = {
        s: 1000,              // seconds
        m: 60 * 1000,         // minutes
        h: 60 * 60 * 1000,    // hours
        d: 24 * 60 * 60 * 1000, // days
        w: 7 * 24 * 60 * 60 * 1000, // weeks
    };

    return value * multipliers[unit];
}

// ============================================================================
// Scheduler Class
// ============================================================================

export class Scheduler extends EventEmitter {
    private jobs: Map<string, ScheduledJob> = new Map();
    private timers: Map<string, NodeJS.Timeout> = new Map();
    private running: Set<string> = new Set();
    private config: SchedulerConfig;

    constructor(config: SchedulerConfig = {}) {
        super();
        this.config = {
            maxConcurrent: config.maxConcurrent || 5,
            defaultRetries: config.defaultRetries || 3,
            ...config,
        };
    }

    /**
     * Register a new job
     */
    register(job: Omit<ScheduledJob, 'runCount' | 'failCount'>): void {
        const fullJob: ScheduledJob = {
            ...job,
            runCount: 0,
            failCount: 0,
        };

        this.jobs.set(job.id, fullJob);

        if (job.enabled) {
            this.scheduleJob(fullJob);
        }

        this.emit('job:registered', fullJob);
    }

    /**
     * Schedule a job's next run
     */
    private scheduleJob(job: ScheduledJob): void {
        // Clear existing timer
        const existingTimer = this.timers.get(job.id);
        if (existingTimer) {
            clearTimeout(existingTimer);
        }

        const interval = parseInterval(job.schedule);
        job.nextRun = new Date(Date.now() + interval);

        const timer = setTimeout(async () => {
            await this.runJob(job.id);

            // Reschedule if still enabled
            const currentJob = this.jobs.get(job.id);
            if (currentJob?.enabled) {
                this.scheduleJob(currentJob);
            }
        }, interval);

        this.timers.set(job.id, timer);
    }

    /**
     * Run a job immediately
     */
    async runJob(jobId: string): Promise<void> {
        const job = this.jobs.get(jobId);
        if (!job) {
            throw new Error(`Job not found: ${jobId}`);
        }

        // Check concurrency limit
        if (this.running.size >= (this.config.maxConcurrent || 5)) {
            this.emit('job:queued', job);
            return;
        }

        // Mark as running
        this.running.add(jobId);
        job.lastRun = new Date();

        const startTime = Date.now();
        this.emit('job:start', job);
        this.config.onJobStart?.(job);

        try {
            await job.handler();

            job.runCount++;
            const duration = Date.now() - startTime;

            this.emit('job:complete', job, duration);
            this.config.onJobComplete?.(job, duration);
        } catch (error) {
            job.failCount++;

            this.emit('job:error', job, error);
            this.config.onJobError?.(job, error as Error);
        } finally {
            this.running.delete(jobId);
        }
    }

    /**
     * Run all enabled jobs immediately
     */
    async runAll(): Promise<void> {
        const enabledJobs = Array.from(this.jobs.values()).filter(j => j.enabled);

        for (const job of enabledJobs) {
            await this.runJob(job.id);
        }
    }

    /**
     * Enable a job
     */
    enable(jobId: string): void {
        const job = this.jobs.get(jobId);
        if (job) {
            job.enabled = true;
            this.scheduleJob(job);
            this.emit('job:enabled', job);
        }
    }

    /**
     * Disable a job
     */
    disable(jobId: string): void {
        const job = this.jobs.get(jobId);
        if (job) {
            job.enabled = false;
            const timer = this.timers.get(jobId);
            if (timer) {
                clearTimeout(timer);
                this.timers.delete(jobId);
            }
            this.emit('job:disabled', job);
        }
    }

    /**
     * Get job status
     */
    getStatus(jobId: string): ScheduledJob | undefined {
        return this.jobs.get(jobId);
    }

    /**
     * Get all jobs
     */
    getAllJobs(): ScheduledJob[] {
        return Array.from(this.jobs.values());
    }

    /**
     * Stop all jobs
     */
    stop(): void {
        for (const timer of this.timers.values()) {
            clearTimeout(timer);
        }
        this.timers.clear();
        this.emit('scheduler:stopped');
    }
}

// ============================================================================
// Default Scheduler Instance
// ============================================================================

export const scheduler = new Scheduler({
    maxConcurrent: 3,
    onJobStart: (job) => {
        console.log(`[Scheduler] Starting job: ${job.name}`);
    },
    onJobComplete: (job, duration) => {
        console.log(`[Scheduler] Completed job: ${job.name} in ${duration}ms`);
    },
    onJobError: (job, error) => {
        console.error(`[Scheduler] Job failed: ${job.name}`, error.message);
    },
});
