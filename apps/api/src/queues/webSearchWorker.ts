/**
 * Web Search Worker — Barrel
 *
 * Thin worker shell that delegates to:
 *   - webSearchProcessor.ts  → Search execution & normalization
 *   - webSearchPersistence.ts → Fan-out writes (OpenSearch + Neo4j)
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../services/redis';
import { createLogger } from '../lib/logger';
import type { WebSearchJobData, WebSearchResult } from '../lib/schemas';
import { executeSearch, buildResult } from './webSearchProcessor';
import { persistResults } from './webSearchPersistence';

const log = createLogger('WebSearchWorker');

export const webSearchWorker = new Worker<WebSearchJobData, WebSearchResult>(
    'web-search',
    async (job: Job<WebSearchJobData>) => {
        const { query, persist, correlationId } = job.data;
        const jobLog = createLogger('WebSearchWorker', correlationId);

        jobLog.info('Processing web search job', { jobId: job.id, query, provider: job.data.provider });

        // Step 1: Search
        await job.updateProgress(10);
        const { searchResult, startTime } = await executeSearch(job.data, correlationId);
        await job.updateProgress(50);

        // Step 2: Normalize
        const result = buildResult(searchResult, job.data, startTime);

        // Step 3: Persist (optional)
        if (persist && result.items.length > 0) {
            await job.updateProgress(60);
            result.persisted = await persistResults(result, correlationId, query, job.id || 'unknown', jobLog);
        }

        await job.updateProgress(100);

        jobLog.info('Job completed', {
            jobId: job.id,
            resultCount: result.items.length,
            processingTimeMs: result.processingTimeMs,
            persisted: result.persisted,
        });

        return result;
    },
    {
        connection,
        concurrency: 3,
        limiter: {
            max: 10,
            duration: 60_000,
        },
    },
);

// Worker events
webSearchWorker.on('completed', (job) => {
    log.info('Job completed', { jobId: job.id, name: job.name });
});

webSearchWorker.on('failed', (job, err) => {
    log.error('Job failed', err, { jobId: job?.id, name: job?.name });
});

webSearchWorker.on('error', (err) => {
    log.error('Worker error', err);
});

export default webSearchWorker;
