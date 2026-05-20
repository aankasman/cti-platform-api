/**
 * Intel Feed Sync Orchestrator
 * 
 * Coordinates syncing from all Intel feed sources.
 * Can run individual feeds or all feeds together.
 */

import { runAlienVaultSync } from './alienvault';
import { runCISASync } from './cisa';
import { runAbuseSSLSync } from './abusessl';
import { syncMitreAttack } from './mitre';
import { runMISPGalaxySync } from './misp-galaxy';
import { runThreatFoxSync } from './threatfox';
import { runURLhausSync } from './urlhaus';
import { runMalwareBazaarSync } from './malwarebazaar';
import { runOpenPhishSync } from './openphish';
import { runNVDSync } from './nvd';
import { createLogger } from '../lib/logger';

const log = createLogger('FeedOrchestrator');

// =============================================================================
// Configuration
// =============================================================================

const FEED_INTERVAL = parseInt(process.env.FEED_SYNC_INTERVAL || '3600000', 10); // 1 hour default

// =============================================================================
// Feed Registry
// =============================================================================

export const feeds = {
    alienvault: {
        name: 'AlienVault OTX',
        sync: runAlienVaultSync,
        interval: 1800000, // 30 minutes
    },
    cisa: {
        name: 'CISA KEV',
        sync: runCISASync,
        interval: 86400000, // 24 hours
    },
    nvd: {
        name: 'NVD CVE',
        sync: runNVDSync,
        interval: 86400000, // 24 hours
    },
    abusessl: {
        name: 'Abuse.ch SSL',
        sync: runAbuseSSLSync,
        interval: 21600000, // 6 hours
    },
    threatfox: {
        name: 'ThreatFox',
        sync: runThreatFoxSync,
        interval: 21600000, // 6 hours
    },
    urlhaus: {
        name: 'URLhaus',
        sync: runURLhausSync,
        interval: 21600000, // 6 hours
    },
    malwarebazaar: {
        name: 'MalwareBazaar',
        sync: runMalwareBazaarSync,
        interval: 21600000, // 6 hours
    },
    openphish: {
        name: 'OpenPhish',
        sync: runOpenPhishSync,
        interval: 21600000, // 6 hours
    },
    mitre: {
        name: 'MITRE ATT&CK',
        sync: syncMitreAttack,
        interval: 604800000, // 7 days (updated weekly)
    },
    mispgalaxy: {
        name: 'MISP Galaxy',
        sync: runMISPGalaxySync,
        interval: 86400000, // 24 hours (daily enrichment)
    },
} as const;

export type FeedName = keyof typeof feeds;

// =============================================================================
// Sync Functions
// =============================================================================

/**
 * Run a single feed sync by name
 */
export async function runFeed(name: FeedName): Promise<void> {
    const feed = feeds[name];
    if (!feed) {
        throw new Error(`Unknown feed: ${name}`);
    }
    log.info(`Running ${feed.name} sync`);
    await feed.sync();
}

/**
 * Run all feeds sequentially
 */
export async function runAllFeeds(): Promise<void> {
    log.info('Running all feeds');

    const startTime = Date.now();
    const results: { name: string; success: boolean; duration: number }[] = [];
    let telemetry: typeof import('../lib/telemetry').workerTelemetry | null = null;

    try {
        const mod = await import('../lib/telemetry');
        telemetry = mod.workerTelemetry;
    } catch { /* telemetry optional */ }

    for (const [key, feed] of Object.entries(feeds)) {
        const feedStart = Date.now();
        log.info(`Starting feed: ${feed.name}`);

        try {
            await feed.sync();
            const duration = Date.now() - feedStart;
            results.push({ name: feed.name, success: true, duration });
            telemetry?.recordSync(key, 0, duration, true);
        } catch (error) {
            const duration = Date.now() - feedStart;
            log.error(`Feed failed: ${feed.name}`, error);
            results.push({ name: feed.name, success: false, duration });
            telemetry?.recordSync(key, 0, duration, false);
        }
    }

    // Summary
    const summary = results.map(r => `${r.success ? '✓' : '✗'} ${r.name}: ${(r.duration / 1000).toFixed(1)}s`).join(', ');
    log.info('All feeds complete', { totalTimeMs: Date.now() - startTime, summary });
}

/**
 * Start daemon mode - runs feeds on their configured intervals
 */
export async function startFeedDaemon(): Promise<void> {
    const intervals = Object.entries(feeds).map(([, f]) => `${f.name}: ${f.interval / 60000}min`).join(', ');
    log.info('Starting daemon mode', { intervals });

    // Initial sync
    await runAllFeeds();

    // Set up intervals for each feed
    for (const [key, feed] of Object.entries(feeds)) {
        setInterval(async () => {
            log.info(`Daemon: scheduled sync starting`, { feed: feed.name });
            try {
                await feed.sync();
            } catch (error) {
                log.error(`Daemon: feed failed`, error, { feed: feed.name });
            }
        }, feed.interval);
    }

    log.info('Feed sync daemon started');
}

// =============================================================================
// CLI Handler — only runs when this file is the direct entry point
// =============================================================================

const isDirectEntry = process.argv[1]?.includes('feeds/index');

if (isDirectEntry) {
    const command = process.argv[2];

    if (command === 'all') {
        runAllFeeds()
            .then(() => process.exit(0))
            .catch((error) => {
                console.error(error);
                process.exit(1);
            });
    } else if (command === 'daemon') {
        startFeedDaemon().catch((error) => {
            console.error(error);
            process.exit(1);
        });
    } else if (command && feeds[command as FeedName]) {
        runFeed(command as FeedName)
            .then(() => process.exit(0))
            .catch((error) => {
                console.error(error);
                process.exit(1);
            });
    } else {
        if (command) console.error(`Unknown command: ${command}`);
        console.log('\nUsage: tsx feeds/index.ts <command>');
        console.log('\nCommands:');
        console.log('  all        - Run all feeds');
        console.log('  daemon     - Run feeds on scheduled intervals');
        console.log('  alienvault    - Run AlienVault OTX sync');
        console.log('  cisa          - Run CISA KEV sync');
        console.log('  nvd           - Run NVD CVE sync');
        console.log('  abusessl      - Run Abuse.ch SSL sync');
        console.log('  threatfox     - Run ThreatFox sync');
        console.log('  urlhaus       - Run URLhaus sync');
        console.log('  malwarebazaar - Run MalwareBazaar sync');
        console.log('  openphish     - Run OpenPhish sync');
        console.log('  mitre         - Run MITRE ATT&CK sync');
        console.log('  mispgalaxy    - Run MISP Galaxy threat actor enrichment');
        process.exit(1);
    }
}
