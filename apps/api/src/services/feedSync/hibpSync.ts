/**
 * HIBP breach catalog sync — Phase 5 #3.
 *
 * Hits the unauthenticated `/breaches` endpoint, upserts every entry
 * into `data_breaches` by name. Free-tier only: NO `/breachedaccount`
 * (paid) and NO `/range` (passwords k-anonymity, different surface).
 *
 * HIBP's terms require:
 *   1. A non-default User-Agent identifying the caller.
 *   2. Rate limit respect (the public /breaches endpoint is generous;
 *      a once-a-day sync is well within bounds).
 *
 * Mapping: HIBP returns PascalCase fields. We translate to our
 * snake_case columns in `mapBreach()`. The full upstream object also
 * gets stashed in `raw_data` so any field we don't model is recoverable.
 */
import { db } from '@rinjani/db';
import { dataBreaches } from '@rinjani/db/schema';
import type { SyncResult } from './types';
import { createLogger } from '../../lib/logger';

const log = createLogger('FeedSync:hibp');

const HIBP_ENDPOINT = 'https://haveibeenpwned.com/api/v3/breaches';
const USER_AGENT = 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)';
const FETCH_TIMEOUT_MS = 30_000;

// ============================================================================
// HIBP response shape (a subset of the documented fields)
// ============================================================================

interface HibpBreach {
    Name: string;
    Title: string;
    Domain?: string;
    BreachDate?: string;     // YYYY-MM-DD
    AddedDate?: string;      // ISO-8601
    ModifiedDate?: string;   // ISO-8601
    PwnCount?: number;
    Description?: string;
    DataClasses?: string[];
    IsVerified?: boolean;
    IsFabricated?: boolean;
    IsSensitive?: boolean;
    IsRetired?: boolean;
    IsSpamList?: boolean;
    LogoPath?: string;
    // Other fields exist (LastModified, IsSubscriptionFree, etc.) — captured
    // in raw_data via passthrough.
    [k: string]: unknown;
}

// ============================================================================
// Mapper — pure, exported for tests
// ============================================================================

function parseDate(value: string | undefined): Date | null {
    if (!value) return null;
    const t = Date.parse(value);
    return Number.isNaN(t) ? null : new Date(t);
}

export interface MappedBreach {
    name: string;
    title: string;
    domain: string | null;
    breachDate: Date | null;
    addedDate: Date | null;
    modifiedDate: Date | null;
    pwnCount: number;
    description: string | null;
    dataClasses: string[];
    isVerified: boolean;
    isFabricated: boolean;
    isSensitive: boolean;
    isRetired: boolean;
    isSpamList: boolean;
    logoPath: string | null;
    rawData: Record<string, unknown>;
}

export function mapHibpBreach(b: HibpBreach): MappedBreach {
    return {
        name: b.Name,
        title: b.Title ?? b.Name,
        domain: b.Domain && b.Domain.length > 0 ? b.Domain : null,
        breachDate: parseDate(b.BreachDate),
        addedDate: parseDate(b.AddedDate),
        modifiedDate: parseDate(b.ModifiedDate),
        pwnCount: typeof b.PwnCount === 'number' ? b.PwnCount : 0,
        description: b.Description ?? null,
        dataClasses: Array.isArray(b.DataClasses)
            ? b.DataClasses.filter((c): c is string => typeof c === 'string')
            : [],
        isVerified: !!b.IsVerified,
        isFabricated: !!b.IsFabricated,
        isSensitive: !!b.IsSensitive,
        isRetired: !!b.IsRetired,
        isSpamList: !!b.IsSpamList,
        logoPath: b.LogoPath ?? null,
        rawData: b as Record<string, unknown>,
    };
}

// ============================================================================
// Sync entrypoint
// ============================================================================

export async function syncHibpBreaches(): Promise<SyncResult> {
    const t0 = Date.now();

    let payload: HibpBreach[];
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        const r = await fetch(HIBP_ENDPOINT, {
            headers: {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json',
            },
            signal: controller.signal,
        });
        clearTimeout(timer);
        if (!r.ok) throw new Error(`HIBP /breaches HTTP ${r.status}`);
        payload = await r.json() as HibpBreach[];
    } catch (err) {
        const msg = (err as Error).message;
        log.error('HIBP fetch failed', { error: msg });
        return {
            success: false,
            pulsesProcessed: 0,
            indicatorsProcessed: 0,
            indicatorsAdded: 0,
            indicatorsUpdated: 0,
            errors: [msg],
        };
    }

    if (!Array.isArray(payload)) {
        const msg = `HIBP /breaches returned non-array payload (${typeof payload})`;
        log.error('HIBP shape mismatch', { error: msg });
        return {
            success: false, pulsesProcessed: 0,
            indicatorsProcessed: 0, indicatorsAdded: 0, indicatorsUpdated: 0,
            errors: [msg],
        };
    }

    let added = 0, updated = 0;
    const errors: string[] = [];
    const now = new Date();

    for (const raw of payload) {
        if (!raw?.Name) {
            errors.push(`skipped entry without Name: ${JSON.stringify(raw).slice(0, 100)}`);
            continue;
        }
        try {
            const m = mapHibpBreach(raw);
            const result = await db.insert(dataBreaches).values({
                name: m.name,
                title: m.title,
                domain: m.domain,
                breachDate: m.breachDate,
                addedDate: m.addedDate,
                modifiedDate: m.modifiedDate,
                pwnCount: m.pwnCount,
                description: m.description,
                dataClasses: m.dataClasses,
                isVerified: m.isVerified,
                isFabricated: m.isFabricated,
                isSensitive: m.isSensitive,
                isRetired: m.isRetired,
                isSpamList: m.isSpamList,
                logoPath: m.logoPath,
                rawData: m.rawData,
                firstSyncedAt: now,
                lastSyncedAt: now,
            }).onConflictDoUpdate({
                target: dataBreaches.name,
                set: {
                    title: m.title,
                    domain: m.domain,
                    breachDate: m.breachDate,
                    addedDate: m.addedDate,
                    modifiedDate: m.modifiedDate,
                    pwnCount: m.pwnCount,
                    description: m.description,
                    dataClasses: m.dataClasses,
                    isVerified: m.isVerified,
                    isFabricated: m.isFabricated,
                    isSensitive: m.isSensitive,
                    isRetired: m.isRetired,
                    isSpamList: m.isSpamList,
                    logoPath: m.logoPath,
                    rawData: m.rawData,
                    lastSyncedAt: now,
                    updatedAt: now,
                },
            }).returning({ id: dataBreaches.id, createdAt: dataBreaches.createdAt });

            const createdAt = result[0]?.createdAt;
            if (createdAt && Math.abs(createdAt.getTime() - now.getTime()) < 2_000) {
                added++;
            } else {
                updated++;
            }
        } catch (err) {
            errors.push(`${raw.Name}: ${(err as Error).message}`);
        }
    }

    log.info('HIBP sync complete', {
        total: payload.length,
        added,
        updated,
        errors: errors.length,
        durationMs: Date.now() - t0,
    });

    return {
        success: errors.length === 0,
        pulsesProcessed: payload.length,
        indicatorsProcessed: payload.length,
        indicatorsAdded: added,
        indicatorsUpdated: updated,
        totalRowsAffected: added + updated,
        errors,
    };
}
