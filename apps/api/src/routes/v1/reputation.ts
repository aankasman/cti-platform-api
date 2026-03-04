/**
 * Community Blocklist & IP/Domain Reputation
 *
 * Inspired by CrowdSec community signals and AbuseIPDB reputation scoring.
 * Aggregates data from existing IOC records, sighting counts, correlation graph,
 * scoring engine, and community reports.
 *
 * Mounts at: /v1/reputation/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth } from '../../middleware/auth';
import { createLogger } from '../../lib/logger';
import { ReputationReportSchema, BulkReputationSchema } from '../../lib/schemas';

const log = createLogger('Reputation');
const reputation = new Hono();
reputation.use('*', requireAuth);

// ============================================================================
// Auto-create Tables
// ============================================================================

const ensureTableOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS reputation_reports (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'other',
                confidence INT NOT NULL DEFAULT 70,
                notes TEXT,
                reported_by TEXT,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_reputation_value ON reputation_reports(value);
            CREATE INDEX IF NOT EXISTS idx_reputation_type ON reputation_reports(type);
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// ============================================================================
// Helpers — Aggregate reputation from multiple sources
// ============================================================================

async function lookupReputation(value: string, type: string) {
    // 1. Check IOC records
    const iocResult = await rawQuery(sql.raw(`
        SELECT id, type, risk_score, confidence, source, tags, first_seen, last_seen, severity,
               (raw_data->>'virusTotal') AS vt_data
        FROM iocs
        WHERE value = '${esc(value)}'
        LIMIT 5
    `));
    const iocRecords = iocResult.rows || [];

    // 2. Count sightings
    const sightingResult = await rawQuery(sql.raw(`
        SELECT COUNT(*) AS total,
               MAX(last_seen) AS latest_sighting
        FROM sightings
        WHERE ioc_id IN (SELECT id FROM iocs WHERE value = '${esc(value)}')
    `));
    const sightings = sightingResult.rows?.[0] as Record<string, unknown> || {};

    // 3. Community reports
    const reportResult = await rawQuery(sql.raw(`
        SELECT category, confidence, notes, created_at
        FROM reputation_reports
        WHERE value = '${esc(value)}' AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC
        LIMIT 10
    `));
    const communityReports = reportResult.rows || [];

    // 4. /24 subnet aggregation (for IPs only)
    let subnetScore: { count: number; avgScore: number } | null = null;
    if (type === 'ip' && /^\d+\.\d+\.\d+\.\d+$/.test(value)) {
        const subnet = value.split('.').slice(0, 3).join('.') + '.%';
        const subnetResult = await rawQuery(sql.raw(`
            SELECT COUNT(*) AS count, COALESCE(AVG(risk_score), 0) AS avg_score
            FROM iocs
            WHERE value LIKE '${esc(subnet)}' AND type = 'ipv4-addr'
        `));
        const sr = subnetResult.rows?.[0] as Record<string, unknown>;
        if (sr) subnetScore = { count: Number(sr.count), avgScore: Math.round(Number(sr.avg_score)) };
    }

    // 5. Compute aggregated reputation score
    const iocScores = (iocRecords as Array<Record<string, unknown>>).map(r => Number(r.risk_score || 0));
    const communityScores = (communityReports as Array<Record<string, unknown>>).map(r => Number(r.confidence || 0));
    const allScores = [...iocScores, ...communityScores];
    const avgScore = allScores.length > 0 ? Math.round(allScores.reduce((a, b) => a + b, 0) / allScores.length) : 0;

    const reputationLevel = avgScore >= 80 ? 'malicious'
        : avgScore >= 60 ? 'suspicious'
            : avgScore >= 30 ? 'neutral'
                : 'clean';

    return {
        value,
        type,
        reputation: { score: avgScore, level: reputationLevel },
        sources: {
            iocRecords: (iocRecords as Array<Record<string, unknown>>).map(r => ({
                id: r.id, source: r.source, riskScore: r.risk_score,
                severity: r.severity, tags: r.tags,
                firstSeen: r.first_seen, lastSeen: r.last_seen,
            })),
            sightings: { total: Number(sightings.total || 0), latestSighting: sightings.latest_sighting || null },
            communityReports: communityReports.length,
            subnetAnalysis: subnetScore,
        },
        totalSignals: iocRecords.length + communityReports.length + Number(sightings.total || 0),
    };
}

function autoDetectType(value: string): string {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return 'ip';
    if (/^[a-f0-9]{32,64}$/i.test(value)) return 'hash';
    if (value.includes('@')) return 'email';
    if (value.startsWith('http')) return 'url';
    return 'domain';
}

// ============================================================================
// GET /reputation/ip/:ip — IP reputation lookup
// ============================================================================

reputation.get('/reputation/ip/:ip', async (c) => {
    await ensureTableOnce();
    const ip = c.req.param('ip');
    const result = await lookupReputation(ip, 'ip');
    return c.json({ success: true, data: result });
});

// ============================================================================
// GET /reputation/domain/:domain — Domain reputation lookup
// ============================================================================

reputation.get('/reputation/domain/:domain', async (c) => {
    await ensureTableOnce();
    const domain = c.req.param('domain');
    const result = await lookupReputation(domain, 'domain');
    return c.json({ success: true, data: result });
});

// ============================================================================
// POST /reputation/bulk — Bulk reputation check
// ============================================================================

reputation.post('/reputation/bulk', async (c) => {
    await ensureTableOnce();
    const body = BulkReputationSchema.parse(await c.req.json().catch(() => ({})));

    const results = await Promise.all(
        body.values.map(async (value) => {
            const type = body.type === 'auto' ? autoDetectType(value) : body.type;
            try {
                return await lookupReputation(value, type);
            } catch (err) {
                return { value, type, reputation: { score: 0, level: 'unknown' }, error: (err as Error).message };
            }
        }),
    );

    return c.json({
        success: true,
        data: { results, total: results.length },
    });
});

// ============================================================================
// POST /reputation/report — Submit community reputation report
// ============================================================================

reputation.post('/reputation/report', async (c) => {
    await ensureTableOnce();
    const body = ReputationReportSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    const expiresAt = new Date(Date.now() + body.ttlHours * 3600 * 1000).toISOString();

    const result = await rawQuery(sql.raw(`
        INSERT INTO reputation_reports (value, type, category, confidence, notes, reported_by, expires_at)
        VALUES ('${esc(body.value)}', '${esc(body.type)}', '${esc(body.category)}',
                ${body.confidence}, ${body.notes ? `'${esc(body.notes)}'` : 'NULL'},
                '${esc(userId)}', '${esc(expiresAt)}')
        RETURNING *
    `));

    log.info('Reputation report submitted', { value: body.value, type: body.type, category: body.category });
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// ============================================================================
// GET /reputation/stats — Reputation system statistics
// ============================================================================

reputation.get('/reputation/stats', async (c) => {
    await ensureTableOnce();

    const [totalResult, categoryResult, topResult] = await Promise.all([
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM reputation_reports WHERE expires_at IS NULL OR expires_at > NOW()`)),
        rawQuery(sql.raw(`SELECT category, COUNT(*) AS count FROM reputation_reports WHERE expires_at IS NULL OR expires_at > NOW() GROUP BY category ORDER BY count DESC`)),
        rawQuery(sql.raw(`SELECT value, type, COUNT(*) AS report_count FROM reputation_reports WHERE expires_at IS NULL OR expires_at > NOW() GROUP BY value, type ORDER BY report_count DESC LIMIT 20`)),
    ]);

    return c.json({
        success: true,
        data: {
            totalActiveReports: Number((totalResult.rows?.[0] as Record<string, unknown>)?.total || 0),
            byCategory: categoryResult.rows || [],
            topReported: topResult.rows || [],
        },
    });
});

export default reputation;
