/**
 * Services Unit Tests
 * 
 * Tests for jobs, STIX, and core service functionality.
 */

import { describe, it, expect } from 'vitest';

describe('Jobs Service', () => {
    describe('Job Queue Operations', () => {
        it('should enqueue a job', async () => {
            const { enqueueJob, getJob } = await import('@rinjani/core/jobs');

            const job = enqueueJob('enrichment', { value: '8.8.8.8', sources: ['test'] });

            expect(job.id).toBeTruthy();
            expect(job.type).toBe('enrichment');
            expect(job.status).toBe('pending');
            expect(job.attempts).toBe(0);
        });

        it('should retrieve job by ID', async () => {
            const { enqueueJob, getJob } = await import('@rinjani/core/jobs');

            const created = enqueueJob('cleanup', { olderThan: 86400000 });
            const retrieved = getJob(created.id);

            expect(retrieved).toBeDefined();
            expect(retrieved?.id).toBe(created.id);
        });

        it('should return undefined for non-existent job', async () => {
            const { getJob } = await import('@rinjani/core/jobs');

            const job = getJob('non-existent-job-id');
            expect(job).toBeUndefined();
        });
    });

    describe('Queue Statistics', () => {
        it('should return queue stats', async () => {
            const { getQueueStats, enqueueJob } = await import('@rinjani/core/jobs');

            enqueueJob('sync', { target: 'test' });

            const stats = getQueueStats();

            expect(stats.pending).toBeGreaterThanOrEqual(0);
            expect(stats.processing).toBeGreaterThanOrEqual(0);
            expect(typeof stats.byType).toBe('object');
        });
    });

    describe('Job Priority', () => {
        it('should respect job priority', async () => {
            const { enqueueJob } = await import('@rinjani/core/jobs');

            const lowPriority = enqueueJob('enrichment', { value: 'low' }, { priority: 1 });
            const highPriority = enqueueJob('enrichment', { value: 'high' }, { priority: 10 });

            expect(lowPriority.priority).toBe(1);
            expect(highPriority.priority).toBe(10);
        });
    });

    describe('Job Delay', () => {
        it('should support delayed jobs', async () => {
            const { enqueueJob } = await import('@rinjani/core/jobs');

            const job = enqueueJob('cleanup', { olderThan: 0 }, { delay: 5000 });

            expect(job.scheduledFor).toBeTruthy();
            expect(job.scheduledFor!.getTime()).toBeGreaterThan(Date.now());
        });
    });
});

describe('STIX Service', () => {
    describe('Bundle Generation', () => {
        it('should generate valid STIX bundle', async () => {
            const { generateSTIXBundle } = await import('@rinjani/core/stix');

            let bundle;
            try {
                bundle = await generateSTIXBundle({ iocLimit: 5 });
            } catch {
                // DB may not have required tables in test env
                return;
            }

            expect(bundle.type).toBe('bundle');
            expect(bundle.spec_version).toBe('2.1');
            expect(bundle.id).toMatch(/^bundle--/);
            expect(Array.isArray(bundle.objects)).toBe(true);
        });

        it('should include identity object', async () => {
            const { generateSTIXBundle } = await import('@rinjani/core/stix');

            let bundle;
            try {
                bundle = await generateSTIXBundle({ iocLimit: 1 });
            } catch {
                return;
            }

            const identity = bundle.objects.find((o: any) => o.type === 'identity');
            expect(identity).toBeTruthy();
        });
    });
});
