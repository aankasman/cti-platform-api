/**
 * /v1/events — Semantic "what changed" stream for the dashboard's
 * attention rail.
 *
 * Distinct from `/v1/notifications` (which is the user-targeted inbox
 * showing per-user notification rows + read state, used by the topbar
 * bell's unread count). Events is platform-wide, **read-only**, and
 * surfaces meaningful threat-intelligence changes the analyst should
 * know about:
 *
 *   • KEV adds        — CVEs that joined CISA's Known Exploited
 *                       Vulnerabilities catalog in the last 7 days
 *   • CVE published   — recent high-CVSS (≥7) CVEs that aren't on KEV
 *                       (KEV-listed CVEs surface above; this avoids
 *                       double-rendering the same identifier)
 *   • Actor added     — new threat-actor rows created in the last 7d
 *                       (e.g. from STIX bundle ingest or analyst entry)
 *   • Pulse           — high-IOC-count pulses from the last 24h (>= 50
 *                       indicators is the "this is meaningful, not just
 *                       another tag" cutoff)
 *   • Sync            — feed-sync runs in the last 24h that failed or
 *                       completed partial — operational events the
 *                       analyst should react to before they cascade
 *
 * All five sources run in parallel and merge into a single timestamp-
 * sorted list. Cheaper than building a dedicated `platform_events`
 * table and a writer for every event kind — at the cost of some
 * query duplication on the read path. Fine while the event taxonomy
 * is small; revisit if it grows past ~10 kinds.
 *
 * No auth: this is a read-only summary used by the always-visible
 * attention rail. Adding auth would mean the rail flickers empty on
 * unauthenticated state — undesirable for an ambient monitoring
 * surface.
 */

import { Hono } from 'hono';
import { db, sql } from '@rinjani/db';

const router = new Hono();

export type EventKind = 'kev' | 'cve' | 'actor' | 'pulse' | 'sync';

export interface PlatformEvent {
    /** Stable per-event id so the client can dedupe / key React rows. */
    id: string;
    kind: EventKind;
    title: string;
    meta: string;
    /** ISO timestamp; the rail sorts and renders relTime from this. */
    timestamp: string;
    /** Optional deep-link target so clicking the row jumps to the entity. */
    href?: string;
}

/* ────────────────────────────────────────────────────────────────────────
   Row shapes — each query returns rows shaped to its source table; the
   `mapXyz` helpers below normalise them into `PlatformEvent`.
   ──────────────────────────────────────────────────────────────────── */

interface KevRow {
    cve_id: string;
    vendor_project: string | null;
    product: string | null;
    cvss_score: string | number | null;
    updated_at: Date | string;
}

interface CveRow {
    cve_id: string;
    vendor_project: string | null;
    product: string | null;
    cvss_score: string | number | null;
    description: string | null;
    published_date: Date | string;
}

interface ActorRow {
    id: string;
    name: string;
    sophistication: string | null;
    description: string | null;
    created_at: Date | string;
}

interface PulseRow {
    id: string;
    otx_id: string | null;
    name: string;
    author: string | null;
    indicator_count: number | null;
    otx_modified: Date | string;
}

interface SyncRow {
    id: string;
    entity_type: string;
    status: string;
    items_processed: unknown;  // JSONB number — coerce on read
    items_failed: unknown;
    error_message: string | null;
    completed_at: Date | string;
}

router.get('/events', async (c) => {
    const limitRaw = Number(c.req.query('limit') ?? 25);
    const limit = Math.min(Math.max(Math.floor(limitRaw) || 25, 1), 100);

    const [kevRows, cveRows, actorRows, pulseRows, syncRows] = await Promise.all([
        // 1. KEV adds — `is_exploited` flipped to true in the last 7d.
        //    Approximation: ORDER BY updated_at DESC for vulns where the
        //    flag is true. The flag flips during the daily kev-sync;
        //    `updated_at` is the row write timestamp, not the upstream
        //    catalog-added date, so this fires once per row update. Good
        //    enough for the rail's 2-hour window in practice.
        db.execute(sql`
            SELECT cve_id, vendor_project, product, cvss_score, updated_at
            FROM vulnerabilities
            WHERE is_exploited = true
              AND updated_at > now() - interval '7 days'
            ORDER BY updated_at DESC
            LIMIT 15
        `) as unknown as Promise<KevRow[]>,

        // 2. High-CVSS new CVEs (NOT on KEV — we don't want to render the
        //    same CVE twice as both a KEV add and a high-severity new
        //    CVE). 7-day window matches KEV.
        db.execute(sql`
            SELECT cve_id, vendor_project, product, cvss_score, description, published_date
            FROM vulnerabilities
            WHERE published_date > now() - interval '7 days'
              AND COALESCE(is_exploited, false) = false
              AND cvss_score IS NOT NULL
              AND cvss_score::numeric >= 7
            ORDER BY published_date DESC
            LIMIT 15
        `) as unknown as Promise<CveRow[]>,

        // 3. New actors tracked. `created_at` is the DB-row creation
        //    time — when our sync first saw this entity. For a brand-new
        //    feed source, this would surface every actor in that feed;
        //    in steady state it surfaces only genuinely-new STIX adds.
        db.execute(sql`
            SELECT id, name, sophistication, description, created_at
            FROM threat_actors
            WHERE created_at > now() - interval '7 days'
            ORDER BY created_at DESC
            LIMIT 15
        `) as unknown as Promise<ActorRow[]>,

        // 4. Significant pulses — high IOC count in last 24h. 50 IOCs is
        //    the rough cutoff between "a tag" and "a campaign-scale
        //    update". Tunable; not configurable today because no analyst
        //    has asked.
        db.execute(sql`
            SELECT id, otx_id, name, author, indicator_count, otx_modified
            FROM pulses
            WHERE otx_modified > now() - interval '24 hours'
              AND indicator_count > 50
            ORDER BY otx_modified DESC
            LIMIT 15
        `) as unknown as Promise<PulseRow[]>,

        // 5. Sync events — failures or partial completions in the last
        //    24h. We don't surface successes here (those are the routine
        //    "did the cron tick" rows); the analyst only needs to react
        //    to broken state.
        db.execute(sql`
            SELECT id, entity_type, status, items_processed, items_failed, error_message, completed_at
            FROM sync_logs
            WHERE status IN ('failed', 'partial')
              AND completed_at > now() - interval '24 hours'
            ORDER BY completed_at DESC
            LIMIT 10
        `) as unknown as Promise<SyncRow[]>,
    ]);

    const events: PlatformEvent[] = [
        ...kevRows.map(mapKev),
        ...cveRows.map(mapCve),
        ...actorRows.map(mapActor),
        ...pulseRows.map(mapPulse),
        ...syncRows.map(mapSync),
    ];

    // Sort by timestamp DESC, then cap to `limit` after the merge so the
    // mix is "most-recent across all kinds" rather than "top-10 of each".
    events.sort((a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );
    const limited = events.slice(0, limit);

    return c.json({
        success: true,
        data: { events: limited, total: events.length },
    });
});

/* ────────────────────────────────────────────────────────────────────────
   Per-kind mapping helpers.
   ──────────────────────────────────────────────────────────────────── */

function mapKev(r: KevRow): PlatformEvent {
    const cvss = parseCvss(r.cvss_score);
    return {
        id: `kev:${r.cve_id}`,
        kind: 'kev',
        title: `${r.cve_id} added to CISA KEV`,
        meta: [
            r.vendor_project || r.product,
            cvss != null ? `CVSS ${cvss.toFixed(1)}` : null,
            'exploited in the wild',
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.updated_at),
        href: `/vulnerabilities/${encodeURIComponent(r.cve_id)}`,
    };
}

function mapCve(r: CveRow): PlatformEvent {
    const cvss = parseCvss(r.cvss_score);
    const inferred = inferVulnTitle(r.description);
    const productLabel = [r.vendor_project, r.product].filter(Boolean).join(' ') || 'product';
    return {
        id: `cve:${r.cve_id}`,
        kind: 'cve',
        title: inferred
            ? `${r.cve_id} — ${productLabel} ${inferred}`
            : `${r.cve_id} — ${productLabel}`,
        meta: [
            cvss != null ? `CVSS ${cvss.toFixed(1)}` : null,
            truncate(r.description, 80),
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.published_date),
        href: `/vulnerabilities/${encodeURIComponent(r.cve_id)}`,
    };
}

function mapActor(r: ActorRow): PlatformEvent {
    return {
        id: `actor:${r.id}`,
        kind: 'actor',
        title: `New actor tracked: ${r.name}`,
        meta: [
            r.sophistication,
            truncate(r.description, 70),
        ].filter(Boolean).join(' · ') || 'no description yet',
        timestamp: iso(r.created_at),
        href: `/actors/${encodeURIComponent(r.id)}`,
    };
}

function mapPulse(r: PulseRow): PlatformEvent {
    return {
        id: `pulse:${r.id}`,
        kind: 'pulse',
        title: truncate(`OTX pulse: ${r.name}`, 80) || `OTX pulse: ${r.name}`,
        meta: [
            r.author,
            r.indicator_count != null ? `${r.indicator_count.toLocaleString()} IOCs` : null,
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.otx_modified),
        href: `/feeds/${encodeURIComponent(r.otx_id || r.id)}`,
    };
}

function mapSync(r: SyncRow): PlatformEvent {
    const processed = Number(r.items_processed ?? 0);
    const failed = Number(r.items_failed ?? 0);
    const word = r.status === 'failed' ? 'failed' : 'partial';
    const feed = humaniseFeedName(r.entity_type);
    return {
        id: `sync:${r.id}`,
        kind: 'sync',
        title: `${feed} sync ${word}`,
        meta: r.error_message
            ? truncate(r.error_message, 90)!
            : [
                processed > 0 ? `${processed.toLocaleString()} processed` : null,
                failed > 0 ? `${failed.toLocaleString()} failed` : null,
            ].filter(Boolean).join(' · ') || 'see runbook',
        timestamp: iso(r.completed_at),
    };
}

/* ────────────────────────────────────────────────────────────────────────
   Utilities.
   ──────────────────────────────────────────────────────────────────── */

function iso(ts: Date | string): string {
    if (typeof ts === 'string') return ts;
    return ts.toISOString();
}

function parseCvss(raw: string | number | null): number | null {
    if (raw == null) return null;
    const n = typeof raw === 'number' ? raw : parseFloat(raw);
    return Number.isFinite(n) ? n : null;
}

function truncate(s: string | null, max: number): string | null {
    if (!s) return null;
    const trimmed = s.trim();
    return trimmed.length > max ? trimmed.slice(0, max - 1).trim() + '…' : trimmed;
}

/**
 * Best-effort guess at the vulnerability class from the CVE description.
 * Only used to enrich the headline ("IntelliJ RCE" > "IntelliJ"); falling
 * back to no suffix is fine.
 */
function inferVulnTitle(description: string | null): string | null {
    if (!description) return null;
    const d = description.toLowerCase();
    if (/\bremote code execution\b|\brce\b/.test(d)) return 'RCE';
    if (/\bcommand injection\b/.test(d))             return 'command injection';
    if (/\bsql injection\b/.test(d))                 return 'SQL injection';
    if (/\b(xss|cross-site scripting)\b/.test(d))    return 'XSS';
    if (/\bprivilege escalation\b/.test(d))          return 'privilege escalation';
    if (/\bbuffer overflow\b/.test(d))               return 'buffer overflow';
    if (/\bdeserialization\b/.test(d))               return 'deserialization vuln';
    if (/\bpath traversal\b/.test(d))                return 'path traversal';
    if (/\b(authentication bypass|auth bypass)\b/.test(d)) return 'auth bypass';
    if (/\binformation disclosure\b/.test(d))        return 'info disclosure';
    if (/\bdenial[- ]of[- ]service\b|\bdos\b/.test(d)) return 'DoS';
    return null;
}

function humaniseFeedName(entityType: string): string {
    // sync_logs.entity_type uses snake_case ("alienvault_pulses",
    // "cisa_kev"). Convert to a readable label for the rail.
    return entityType
        .split(/[_-]/)
        .map(p => p.charAt(0).toUpperCase() + p.slice(1))
        .join(' ');
}

export default router;
