/**
 * V3 Worker Entry Point — BullMQ Workers + Feed Sync
 *
 * Standalone process that runs all background job workers independently
 * of the Hono HTTP server. This enables independent scaling of
 * compute-heavy work (enrichment, AI analysis, Neo4j sync, etc.)
 * from latency-sensitive API request handling.
 *
 * Usage:
 *   pnpm --filter @rinjani/worker start:workers
 *   pnpm --filter @rinjani/worker dev:workers
 */

// Load environment variables from project root .env file
import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '../../..');
config({ path: join(projectRoot, '.env') });

// ============================================================================
// BullMQ Workers (from apps/api/src/queues)
// ============================================================================

// Workers are defined in apps/api/src/queues/workers/ and auto-register
// their event handlers on import. We import startWorkers/stopWorkers
// to coordinate startup and graceful shutdown.
import { startWorkers, stopWorkers } from '../../api/src/queues/workers/workerEvents.js';

// Web search worker (queue-driven scraping pipeline)
import '../../api/src/queues/webSearchWorker.js';

// Scheduled jobs (cron-like repeatable BullMQ jobs)
import { setupScheduledJobs } from '../../api/src/queues/scheduler.js';

// Redis connection for graceful shutdown
import { shutdownRedis } from '../../api/src/services/redis.js';

// ============================================================================
// Feed Sync (existing daemon)
// ============================================================================

import { syncCISA } from './feeds/cisa.js';
import { syncAlienVault } from './feeds/alienvault.js';
import { syncMITRE } from './feeds/mitre.js';

const SYNC_INTERVAL = parseInt(process.env.SYNC_INTERVAL || '3600000'); // 1 hour default
const ENABLE_FEED_SYNC = process.env.ENABLE_FEED_SYNC !== 'false'; // enabled by default

// ============================================================================
// Feed Sync Functions
// ============================================================================

async function runAllFeeds() {
    console.log('\n[Worker] Starting feed sync cycle...\n');

    const results = {
        cisa: { success: false, processed: 0, errors: [] as string[] },
        alienvault: { success: false, processed: 0, errors: [] as string[] },
        mitre: { success: false, processed: 0, errors: [] as string[] },
    };

    try {
        console.log('[CISA] Starting sync...');
        const cisaResult = await syncCISA();
        results.cisa.success = cisaResult.failed === 0 && cisaResult.processed > 0;
        results.cisa.processed = cisaResult.processed;
        console.log(`[CISA] ✅ Synced ${cisaResult.processed} vulnerabilities`);
    } catch (error) {
        results.cisa.errors.push((error as Error).message);
        console.error('[CISA] ❌ Sync failed:', error);
    }

    try {
        console.log('[AlienVault] Starting sync...');
        const otxResult = await syncAlienVault();
        results.alienvault.success = otxResult.failed === 0 && otxResult.processed > 0;
        results.alienvault.processed = otxResult.processed;
        console.log(`[AlienVault] ✅ Synced ${otxResult.processed} indicators`);
    } catch (error) {
        results.alienvault.errors.push((error as Error).message);
        console.error('[AlienVault] ❌ Sync failed:', error);
    }

    try {
        console.log('[MITRE] Starting sync...');
        const mitreResult = await syncMITRE();
        results.mitre.success = mitreResult.failed === 0 && mitreResult.processed > 0;
        results.mitre.processed = mitreResult.processed;
        console.log(`[MITRE] ✅ Synced ${mitreResult.processed} techniques`);
    } catch (error) {
        results.mitre.errors.push((error as Error).message);
        console.error('[MITRE] ❌ Sync failed:', error);
    }

    const totalProcessed = results.cisa.processed + results.alienvault.processed + results.mitre.processed;
    const successCount = [results.cisa.success, results.alienvault.success, results.mitre.success].filter(Boolean).length;
    console.log(`\n[Worker] Sync cycle complete: ${successCount}/3 feeds successful, ${totalProcessed} total items\n`);

    return results;
}

// ============================================================================
// Main — Boot Everything
// ============================================================================

async function main() {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║         V3 Worker Process (Standalone)                    ║
╠═══════════════════════════════════════════════════════════╣
║  BullMQ Workers:  10 (feed-sync, enrichment, AI, Neo4j,  ║
║                   nexus, CVE, notifications, alerts,      ║
║                   retention, web-search)                   ║
║  Feed Sync:       ${ENABLE_FEED_SYNC ? 'Enabled' : 'Disabled'} (interval: ${(SYNC_INTERVAL / 1000 / 60).toFixed(0)}min)${' '.repeat(Math.max(0, 18 - (ENABLE_FEED_SYNC ? 'Enabled' : 'Disabled').length - (SYNC_INTERVAL / 1000 / 60).toFixed(0).length))}║
║  Scheduled Jobs:  cron-based repeatable jobs              ║
╚═══════════════════════════════════════════════════════════╝
`);

    // 1. Start all BullMQ workers
    console.log('[Worker] Starting BullMQ workers...');
    startWorkers();
    console.log('[Worker] ✅ All BullMQ workers started');

    // 2. Setup scheduled jobs (cron-like repeatable BullMQ jobs)
    console.log('[Worker] Setting up scheduled jobs...');
    try {
        await setupScheduledJobs();
        console.log('[Worker] ✅ Scheduled jobs configured');
    } catch (err) {
        console.warn('[Worker] ⚠️ Scheduled jobs setup failed:', (err as Error).message);
    }

    // 3. Start feed sync daemon (if enabled)
    if (ENABLE_FEED_SYNC) {
        console.log('[Worker] Starting feed sync daemon...');
        // Initial sync on startup
        await runAllFeeds().catch(err => {
            console.error('[Worker] Initial feed sync failed:', err);
        });

        // Then run on interval
        setInterval(async () => {
            await runAllFeeds().catch(err => {
                console.error('[Worker] Feed sync cycle failed:', err);
            });
        }, SYNC_INTERVAL);

        console.log(`[Worker] ✅ Feed sync daemon running (next sync in ${(SYNC_INTERVAL / 1000 / 60).toFixed(0)} minutes)`);
    } else {
        console.log('[Worker] ⏭️  Feed sync disabled (ENABLE_FEED_SYNC=false)');
    }

    // 4. Graceful shutdown handler
    const shutdown = async (signal: string) => {
        console.log(`[Worker] Received ${signal}, shutting down gracefully...`);
        await Promise.allSettled([
            stopWorkers(),
            shutdownRedis(),
        ]);
        console.log('[Worker] All workers stopped, exiting');
        process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    console.log('[Worker] ✅ Worker process fully started');
}

main().catch((error) => {
    console.error('[Worker] Fatal error:', error);
    process.exit(1);
});
