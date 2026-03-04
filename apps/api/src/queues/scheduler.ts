/**
 * BullMQ Scheduled Jobs
 * 
 * Configures repeatable jobs for periodic feed syncs and maintenance tasks.
 */

import { feedSyncQueue, enrichmentQueue, aiAnalysisQueue, nexusQueue, cveEnrichmentQueue, maintenanceQueue } from './index';
import { createLogger } from '../lib/logger';

const log = createLogger('Scheduler');

// ============================================================================
// Schedule Configuration
// ============================================================================

interface ScheduleConfig {
    name: string;
    cron: string;
    description: string;
}

const SCHEDULES: Record<string, ScheduleConfig> = {
    // =========================================================================
    // HIGH-FREQUENCY SYNCS (Real-time threat intelligence)
    // =========================================================================

    // Every 15 minutes - OTX pulses for near real-time threat detection
    otxSync: {
        name: 'otx-sync',
        cron: '*/15 * * * *', // Every 15 minutes
        description: 'Sync AlienVault OTX pulses (high-frequency)',
    },

    // Every hour - CISA KEV (new exploits are critical)
    cisaSync: {
        name: 'cisa-sync',
        cron: '0 * * * *', // At minute 0 of every hour
        description: 'Sync CISA Known Exploited Vulnerabilities',
    },

    // Daily at 2:00 AM - NVD CVE database (large dataset, low frequency)
    nvdSync: {
        name: 'nvd-sync',
        cron: '0 2 * * *', // Daily at 2 AM
        description: 'Sync NIST NVD CVE database (recently modified)',
    },

    // Every 30 minutes - All feeds combined for comprehensive coverage
    allFeedsSync: {
        name: 'all-feeds-sync',
        cron: '*/30 * * * *', // Every 30 minutes
        description: 'Sync all threat intelligence feeds',
    },

    // Daily at 3:00 AM — CVE enrichment (CVSS backfill + dates)
    cveEnrichment: {
        name: 'cve-enrichment-daily',
        cron: '0 3 * * *', // Daily at 3 AM (after NVD sync at 2 AM)
        description: 'Enrich CVEs missing CVSS scores and published dates',
    },

    // =========================================================================
    // IOC FEED SYNCS (Abuse.ch ecosystem + OpenPhish)
    // =========================================================================

    abusesslSync: {
        name: 'abusessl-sync',
        cron: '30 */6 * * *', // Every 6 hours at :30
        description: 'Sync Abuse.ch SSL blacklist',
    },
    threatfoxSync: {
        name: 'threatfox-sync',
        cron: '0 */6 * * *', // Every 6 hours at :00
        description: 'Sync ThreatFox IOCs',
    },
    urlhausSync: {
        name: 'urlhaus-sync',
        cron: '15 */6 * * *', // Every 6 hours at :15
        description: 'Sync URLhaus malicious URLs',
    },
    malwarebazaarSync: {
        name: 'malwarebazaar-sync',
        cron: '45 */6 * * *', // Every 6 hours at :45
        description: 'Sync MalwareBazaar hashes',
    },
    openphishSync: {
        name: 'openphish-sync',
        cron: '0 */4 * * *', // Every 4 hours
        description: 'Sync OpenPhish phishing URLs',
    },

    // =========================================================================
    // KNOWLEDGE BASE SYNCS (lower frequency)
    // =========================================================================

    mitreSync: {
        name: 'mitre-sync',
        cron: '0 4 * * 0', // Weekly on Sunday at 4 AM
        description: 'Sync MITRE ATT&CK framework',
    },
    mispGalaxySync: {
        name: 'mispgalaxy-sync',
        cron: '0 5 * * *', // Daily at 5 AM
        description: 'Sync MISP Galaxy threat actor enrichment',
    },

    // =========================================================================
    // CONFIGURABLE VIA ENV (for rate limiting considerations)
    // =========================================================================
    // Override with: FEED_SYNC_CRON_OTX, FEED_SYNC_CRON_CISA, FEED_SYNC_CRON_ALL

    // =========================================================================
    // NEXUS WEB INTELLIGENCE (Exa Webset sync)
    // =========================================================================

    // Every 15 minutes - Pull new items from all Exa Websets (real-time threat intel)
    nexusSync: {
        name: 'nexus-webset-sync',
        cron: '*/15 * * * *', // Every 15 minutes — CTI needs near-real-time sync
        description: 'Sync all Nexus Webset items to local database',
    },

    // =========================================================================
    // MAINTENANCE (data lifecycle)
    // =========================================================================

    confidenceDecay: {
        name: 'confidence-decay',
        cron: '0 1 * * *', // Daily at 1 AM
        description: 'Apply exponential decay to IOC confidence scores',
    },
    dataRetention: {
        name: 'data-retention',
        cron: '30 3 * * 0', // Weekly on Sunday at 3:30 AM
        description: 'Prune old audit logs, resolved alerts, and archive stale IOCs',
    },
};

// ============================================================================
// Setup Functions
// ============================================================================

/**
 * Setup all scheduled jobs
 */
export async function setupScheduledJobs(): Promise<void> {
    log.info('Setting up scheduled jobs');

    try {
        // OTX sync every 6 hours
        await feedSyncQueue.add(
            SCHEDULES.otxSync.name,
            { source: 'otx' as const, options: { limit: 50 } },
            {
                repeat: { pattern: SCHEDULES.otxSync.cron },
                jobId: 'scheduled-otx-sync',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.otxSync.description, cron: SCHEDULES.otxSync.cron });

        // CISA sync daily
        await feedSyncQueue.add(
            SCHEDULES.cisaSync.name,
            { source: 'cisa' as const },
            {
                repeat: { pattern: SCHEDULES.cisaSync.cron },
                jobId: 'scheduled-cisa-sync',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.cisaSync.description, cron: SCHEDULES.cisaSync.cron });

        // NVD sync daily at 2 AM
        await feedSyncQueue.add(
            SCHEDULES.nvdSync.name,
            { source: 'nvd' as const, options: { limit: 100 } },
            {
                repeat: { pattern: SCHEDULES.nvdSync.cron },
                jobId: 'scheduled-nvd-sync',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.nvdSync.description, cron: SCHEDULES.nvdSync.cron });

        // Nexus Webset sync every 15 minutes (real-time CTI pipeline)
        await nexusQueue.add(
            SCHEDULES.nexusSync.name,
            { type: 'sync-all-websets' as const },
            {
                repeat: { pattern: SCHEDULES.nexusSync.cron },
                jobId: 'scheduled-nexus-sync',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.nexusSync.description, cron: SCHEDULES.nexusSync.cron });

        // CVE enrichment daily at 3 AM
        await cveEnrichmentQueue.add(
            SCHEDULES.cveEnrichment.name,
            { type: 'all' as const, batchSize: 100 },
            {
                repeat: { pattern: SCHEDULES.cveEnrichment.cron },
                jobId: 'scheduled-cve-enrichment',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.cveEnrichment.description, cron: SCHEDULES.cveEnrichment.cron });

        // IOC feeds (abuse.ch ecosystem + OpenPhish)
        const iocFeeds = [
            { schedule: SCHEDULES.abusesslSync, source: 'abusessl' as const },
            { schedule: SCHEDULES.threatfoxSync, source: 'threatfox' as const },
            { schedule: SCHEDULES.urlhausSync, source: 'urlhaus' as const },
            { schedule: SCHEDULES.malwarebazaarSync, source: 'malwarebazaar' as const },
            { schedule: SCHEDULES.openphishSync, source: 'openphish' as const },
            { schedule: SCHEDULES.mitreSync, source: 'mitre' as const },
            { schedule: SCHEDULES.mispGalaxySync, source: 'mispgalaxy' as const },
        ];
        for (const { schedule, source } of iocFeeds) {
            await feedSyncQueue.add(
                schedule.name,
                { source },
                {
                    repeat: { pattern: schedule.cron },
                    jobId: `scheduled-${source}-sync`,
                }
            );
            log.info('Scheduled job added', { job: schedule.description, cron: schedule.cron });
        }

        log.info('All scheduled jobs configured');

        // Maintenance jobs
        await maintenanceQueue.add(
            SCHEDULES.confidenceDecay.name,
            { type: 'confidence-decay' },
            {
                repeat: { pattern: SCHEDULES.confidenceDecay.cron },
                jobId: 'scheduled-confidence-decay',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.confidenceDecay.description, cron: SCHEDULES.confidenceDecay.cron });

        await maintenanceQueue.add(
            SCHEDULES.dataRetention.name,
            { type: 'data-retention' },
            {
                repeat: { pattern: SCHEDULES.dataRetention.cron },
                jobId: 'scheduled-data-retention',
            }
        );
        log.info('Scheduled job added', { job: SCHEDULES.dataRetention.description, cron: SCHEDULES.dataRetention.cron });
    } catch (err) {
        log.error('Failed to setup scheduled jobs', err as Error);
    }
}

/**
 * Get all repeatable jobs
 */
export async function getScheduledJobs() {
    const [feedSyncJobs, nexusJobs, maintenanceJobs] = await Promise.all([
        feedSyncQueue.getRepeatableJobs(),
        nexusQueue.getRepeatableJobs(),
        maintenanceQueue.getRepeatableJobs(),
    ]);

    return {
        feedSync: feedSyncJobs,
        nexusIntel: nexusJobs,
        maintenance: maintenanceJobs,
    };
}

/**
 * Remove all scheduled jobs
 */
export async function clearScheduledJobs(): Promise<void> {
    log.info('Clearing all scheduled jobs');

    const feedSyncJobs = await feedSyncQueue.getRepeatableJobs();
    const nexusJobs = await nexusQueue.getRepeatableJobs();
    const maintenanceJobs = await maintenanceQueue.getRepeatableJobs();

    for (const job of feedSyncJobs) {
        await feedSyncQueue.removeRepeatableByKey(job.key);
    }
    for (const job of nexusJobs) {
        await nexusQueue.removeRepeatableByKey(job.key);
    }
    for (const job of maintenanceJobs) {
        await maintenanceQueue.removeRepeatableByKey(job.key);
    }

    log.info('All scheduled jobs cleared');
}

/**
 * Trigger an immediate sync (bypasses schedule)
 */
export async function triggerImmediateSync(source: 'otx' | 'cisa' | 'nvd' | 'all' = 'all') {
    const job = await feedSyncQueue.add(
        `immediate-${source}-sync`,
        { source, options: { limit: 100 } },
        { priority: 1 } // High priority
    );

    log.info('Triggered immediate sync', { source, jobId: job.id });
    return job;
}
