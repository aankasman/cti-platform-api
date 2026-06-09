/**
 * Brand monitoring sweep — Phase 5 #1.
 *
 * Pulls every enabled `monitored_domains` row, generates dnstwist-style
 * permutations, DNS-resolves each, and upserts a `brand_alerts` row for
 * anything that resolves. The pure permutation generator + scoring lives
 * in `@rinjani/core/domainPermutations`; this service is the DNS I/O
 * + DB upsert layer.
 *
 * Run modes:
 *   - sweepAllMonitoredDomains() — invoked by the scheduler every 6h
 *   - sweepMonitoredDomain(id)   — invoked by POST .../sweep for ad-hoc runs
 *
 * Concurrency: DNS resolves run in batches of 16 to avoid hammering the
 * system resolver. Per-permutation timeout 3 s; failures become
 * `dns_state='error'` so the row is recorded but doesn't poison the
 * scoring side.
 */
import { promises as dnsPromises } from 'node:dns';
import { db, eq, sql } from '@rinjani/db';
import { monitoredDomains, brandAlerts } from '@rinjani/db/schema';
import type { BrandAlertDnsState } from '@rinjani/db/schema';
import {
    generatePermutations, scoreAlert,
    type Permutation,
} from '@rinjani/core/domainPermutations';
import { createLogger } from '../lib/logger';

const log = createLogger('BrandMonitor');

const RESOLVE_TIMEOUT_MS = 3_000;
const RESOLVE_BATCH = 16;
// Per-domain ceiling — keeps even the worst-case 12-char label sweep bounded.
const MAX_PERMUTATIONS_PER_DOMAIN = 2_000;

// ============================================================================
// DNS resolver — single permutation
// ============================================================================

interface ResolveOutcome {
    state: BrandAlertDnsState;
    /** Comma-separated A records, joined for storage in the `ip_addresses` text column. */
    ipAddresses: string | null;
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
    return new Promise<T | null>((resolve) => {
        const timer = setTimeout(() => resolve(null), ms).unref?.();
        p.then(v => { if (timer) clearTimeout(timer as unknown as NodeJS.Timeout); resolve(v); })
         .catch(() => { if (timer) clearTimeout(timer as unknown as NodeJS.Timeout); resolve(null); });
    });
}

export async function resolveDomain(domain: string): Promise<ResolveOutcome> {
    // resolve4 throws NXDOMAIN/refused/etc., which we trap and translate.
    try {
        const a = await withTimeout(dnsPromises.resolve4(domain), RESOLVE_TIMEOUT_MS);
        if (a && a.length > 0) return { state: 'active', ipAddresses: a.join(',') };
    } catch (err) {
        const code = (err as { code?: string }).code;
        if (code !== 'ENOTFOUND' && code !== 'ENODATA') {
            log.debug('resolve4 transient error', { domain, code });
        }
    }
    // No A record — try MX so we catch the "registered for phishing email" case.
    try {
        const mx = await withTimeout(dnsPromises.resolveMx(domain), RESOLVE_TIMEOUT_MS);
        if (mx && mx.length > 0) return { state: 'mx_only', ipAddresses: null };
    } catch (err) {
        const code = (err as { code?: string }).code;
        if (code === 'ENOTFOUND') return { state: 'nx', ipAddresses: null };
        if (code !== 'ENODATA') return { state: 'error', ipAddresses: null };
    }
    return { state: 'nx', ipAddresses: null };
}

// ============================================================================
// Sweep — one domain
// ============================================================================

export interface SweepSummary {
    monitoredDomainId: string;
    apex: string;
    permutationsGenerated: number;
    permutationsChecked: number;
    /** Hits = anything not in (nx, error) — i.e. anything actually resolving. */
    hitsCreated: number;
    hitsUpdated: number;
    durationMs: number;
}

interface SweepRow {
    id: string;
    apexDomain: string;
}

export async function sweepMonitoredDomain(monitoredDomainId: string): Promise<SweepSummary> {
    const [row] = await db.select({
        id: monitoredDomains.id,
        apexDomain: monitoredDomains.apexDomain,
    })
        .from(monitoredDomains)
        .where(eq(monitoredDomains.id, monitoredDomainId))
        .limit(1);
    if (!row) throw new Error(`monitored_domain ${monitoredDomainId} not found`);
    return sweepRow(row);
}

export async function sweepAllMonitoredDomains(): Promise<SweepSummary[]> {
    const rows = await db.select({
        id: monitoredDomains.id,
        apexDomain: monitoredDomains.apexDomain,
    })
        .from(monitoredDomains)
        .where(eq(monitoredDomains.enabled, true));

    const summaries: SweepSummary[] = [];
    for (const row of rows) {
        try {
            summaries.push(await sweepRow(row));
        } catch (err) {
            log.warn('sweep failed for domain', { id: row.id, apex: row.apexDomain, error: (err as Error).message });
        }
    }
    return summaries;
}

async function sweepRow(row: SweepRow): Promise<SweepSummary> {
    const t0 = Date.now();
    const allPerms = generatePermutations(row.apexDomain).slice(0, MAX_PERMUTATIONS_PER_DOMAIN);

    let hitsCreated = 0, hitsUpdated = 0, permutationsChecked = 0;

    // Process in batches so we don't overwhelm the system resolver.
    for (let i = 0; i < allPerms.length; i += RESOLVE_BATCH) {
        const batch = allPerms.slice(i, i + RESOLVE_BATCH);
        const outcomes = await Promise.all(batch.map(async (p) => ({
            perm: p,
            outcome: await resolveDomain(p.value),
        })));
        permutationsChecked += outcomes.length;

        // Only upsert rows for permutations that actually resolved. The nx
        // and error cases are too noisy to persist on a normal sweep.
        const hits = outcomes.filter(o => o.outcome.state === 'active' || o.outcome.state === 'mx_only');
        for (const { perm, outcome } of hits) {
            const upserted = await upsertHit(row, perm, outcome);
            if (upserted === 'created') hitsCreated++; else hitsUpdated++;
        }
    }

    await db.update(monitoredDomains)
        .set({ lastSweptAt: new Date(), updatedAt: new Date() })
        .where(eq(monitoredDomains.id, row.id));

    const summary: SweepSummary = {
        monitoredDomainId: row.id,
        apex: row.apexDomain,
        permutationsGenerated: allPerms.length,
        permutationsChecked,
        hitsCreated,
        hitsUpdated,
        durationMs: Date.now() - t0,
    };
    log.info('Sweep complete', summary as unknown as Record<string, unknown>);
    return summary;
}

async function upsertHit(
    parent: SweepRow,
    perm: Permutation,
    outcome: ResolveOutcome,
): Promise<'created' | 'updated'> {
    const now = new Date();
    const score = scoreAlert({
        apex: parent.apexDomain,
        permutation: perm.value,
        dnsState: outcome.state,
        firstSeenAt: now,
        now,
    });

    // INSERT … ON CONFLICT (monitored_domain_id, permutation) DO UPDATE
    const result = await db.insert(brandAlerts).values({
        monitoredDomainId: parent.id,
        permutation: perm.value,
        algorithm: perm.algorithm,
        dnsState: outcome.state,
        ipAddresses: outcome.ipAddresses,
        score,
        firstSeenAt: now,
        lastCheckedAt: now,
    }).onConflictDoUpdate({
        target: [brandAlerts.monitoredDomainId, brandAlerts.permutation],
        set: {
            dnsState: outcome.state,
            ipAddresses: outcome.ipAddresses,
            // Recompute score against the EXISTING firstSeenAt — preserves the
            // freshness bonus for things first observed weeks ago.
            score: sql`LEAST(100, GREATEST(0,
                40
                + CASE WHEN ${brandAlerts.firstSeenAt} > NOW() - INTERVAL '7 days' THEN 20 ELSE 0 END
                + CASE WHEN split_part(${brandAlerts.permutation}, '.', -1)
                       = split_part(${parent.apexDomain}, '.', -1)
                       THEN 20 ELSE 0 END
            ))`,
            lastCheckedAt: now,
            updatedAt: now,
        },
    }).returning({ createdAt: brandAlerts.createdAt });

    // Drizzle returning gives us the row's createdAt; if it's close to `now`
    // it's a fresh insert.
    const ts = result[0]?.createdAt?.getTime?.() ?? now.getTime();
    return Math.abs(ts - now.getTime()) < 2_000 ? 'created' : 'updated';
}
