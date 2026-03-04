/**
 * V3 Worker Entry Point - Standalone Mode
 * 
 * Runs intel feed workers independently.
 * Syncs directly from public threat intel sources:
 * - CISA KEV (Known Exploited Vulnerabilities)
 * - AlienVault OTX (Open Threat Exchange)
 * - MITRE ATT&CK (Tactics, Techniques, Procedures)
 */

// Load environment variables from project root .env file
import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '../../..');
config({ path: join(projectRoot, '.env') });

console.log('[Worker] Loaded DATABASE_URL:', process.env.DATABASE_URL ? '✅ Set' : '❌ Missing');

import { syncCISA } from './feeds/cisa.js';
import { syncAlienVault } from './feeds/alienvault.js';
import { syncMITRE } from './feeds/mitre.js';

const SYNC_INTERVAL = parseInt(process.env.SYNC_INTERVAL || '3600000'); // 1 hour default

console.log(`
╔═══════════════════════════════════════════════════════════╗
║         V3 Threat Intel Worker (Standalone)               ║
╠═══════════════════════════════════════════════════════════╣
║  Mode:   Direct feed sync (standalone)                    ║
║  Feeds:  CISA KEV, AlienVault OTX, MITRE ATT&CK           ║
║  Interval: ${(SYNC_INTERVAL / 1000 / 60).toFixed(0)} minutes                                        ║
╚═══════════════════════════════════════════════════════════╝
`);

/**
 * Run all feed syncs
 */
async function runAllFeeds() {
    console.log('\n[Worker] Starting feed sync cycle...\n');

    const results = {
        cisa: { success: false, processed: 0, errors: [] as string[] },
        alienvault: { success: false, processed: 0, errors: [] as string[] },
        mitre: { success: false, processed: 0, errors: [] as string[] },
    };

    // CISA KEV Sync
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

    // AlienVault OTX Sync
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

    // MITRE ATT&CK Sync
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

    // Summary
    const totalProcessed = results.cisa.processed + results.alienvault.processed + results.mitre.processed;
    const successCount = [results.cisa.success, results.alienvault.success, results.mitre.success].filter(Boolean).length;

    console.log(`\n[Worker] Sync cycle complete: ${successCount}/3 feeds successful, ${totalProcessed} total items\n`);

    return results;
}

/**
 * Start daemon mode
 */
async function startDaemon() {
    console.log('[Worker] Starting daemon mode...\n');

    // Run immediately on startup
    await runAllFeeds();

    // Then run on interval
    setInterval(async () => {
        await runAllFeeds();
    }, SYNC_INTERVAL);

    console.log(`[Worker] Daemon running. Next sync in ${(SYNC_INTERVAL / 1000 / 60).toFixed(0)} minutes.`);
}

/**
 * Run once mode (for cron jobs)
 */
async function runOnce() {
    console.log('[Worker] Running in one-shot mode...\n');
    await runAllFeeds();
    console.log('[Worker] One-shot complete. Exiting.');
    process.exit(0);
}

// Main
const mode = process.argv.includes('--once') ? 'once' : 'daemon';

if (mode === 'once') {
    runOnce().catch((error) => {
        console.error('[Worker] Fatal error:', error);
        process.exit(1);
    });
} else {
    startDaemon().catch((error) => {
        console.error('[Worker] Fatal error:', error);
        process.exit(1);
    });
}
