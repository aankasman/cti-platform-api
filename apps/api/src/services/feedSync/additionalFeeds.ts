/**
 * Additional Feed Sync Wrappers
 *
 * Wraps worker feed scripts for use by the API-side BullMQ feedSyncWorker.
 * Uses dynamic imports with @ts-ignore since worker scripts are outside
 * the API tsconfig rootDir — they resolve fine at runtime (tsx).
 */

import type { SyncResult } from './types';

function normalise(
    src: { processed: number; failed: number; errors: string[] },
): SyncResult {
    return {
        success: src.failed === 0 || src.processed > 0,
        pulsesProcessed: 1,
        indicatorsProcessed: src.processed + src.failed,
        indicatorsAdded: src.processed,
        indicatorsUpdated: 0,
        errors: src.errors,
    };
}

function emptyResult(success: boolean, errors: string[] = []): SyncResult {
    return {
        success,
        pulsesProcessed: success ? 1 : 0,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors,
    };
}

export async function syncAbuseSSLFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncAbuseSSL } = await import('../../../../worker/src/feeds/abusessl');
    return normalise(await syncAbuseSSL());
}

export async function syncThreatFoxFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncThreatFox } = await import('../../../../worker/src/feeds/threatfox');
    return normalise(await syncThreatFox());
}

export async function syncURLhausFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncURLhaus } = await import('../../../../worker/src/feeds/urlhaus');
    return normalise(await syncURLhaus());
}

export async function syncMalwareBazaarFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncMalwareBazaar } = await import('../../../../worker/src/feeds/malwarebazaar');
    return normalise(await syncMalwareBazaar());
}

export async function syncOpenPhishFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncOpenPhish } = await import('../../../../worker/src/feeds/openphish');
    return normalise(await syncOpenPhish());
}

export async function syncMITREFeed(): Promise<SyncResult> {
    try {
        // @ts-ignore
        const { syncMitreAttack } = await import('../../../../worker/src/feeds/mitre');
        await syncMitreAttack();
        return emptyResult(true);
    } catch (err) {
        return emptyResult(false, [(err as Error).message]);
    }
}

export async function syncMISPGalaxyFeed(): Promise<SyncResult> {
    try {
        // @ts-ignore
        const { runMISPGalaxySync } = await import('../../../../worker/src/feeds/misp-galaxy');
        await runMISPGalaxySync();
        return emptyResult(true);
    } catch (err) {
        return emptyResult(false, [(err as Error).message]);
    }
}

export async function syncEPSSFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncEPSS } = await import('../../../../worker/src/feeds/epss');
    return normalise(await syncEPSS().then((r: { matched: number; failed: number; errors: string[] }) =>
        // EPSS reports `matched` (rows actually updated) as the meaningful
        // count; map it onto the standard `processed` field so the rest
        // of the pipeline (feed_sync_runs.items_ingested) reflects useful
        // work done rather than "rows present in the upstream feed".
        ({ processed: r.matched, failed: r.failed, errors: r.errors }),
    ));
}
