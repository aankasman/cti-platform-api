/**
 * Scheduled Intelligence Reports
 *
 * Automated periodic report generation and delivery.
 * Leverages existing export/report generator and notification services.
 *
 * Mounts at: /v1/reports/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import { CreateReportScheduleSchema, UpdateReportScheduleSchema } from '../../lib/schemas';

const log = createLogger('ScheduledReports');
const router = new Hono();
router.use('*', requireAuth);

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS report_schedules (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                name TEXT NOT NULL,
                schedule TEXT NOT NULL DEFAULT 'weekly',
                format TEXT NOT NULL DEFAULT 'markdown',
                scope TEXT NOT NULL DEFAULT 'summary',
                filters JSONB DEFAULT '{}',
                delivery JSONB DEFAULT '{"inApp":true}',
                enabled BOOLEAN DEFAULT true,
                last_run_at TIMESTAMPTZ,
                next_run_at TIMESTAMPTZ,
                owner_id TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS generated_reports (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                schedule_id TEXT REFERENCES report_schedules(id) ON DELETE SET NULL,
                name TEXT NOT NULL,
                format TEXT NOT NULL DEFAULT 'markdown',
                content TEXT NOT NULL,
                scope TEXT NOT NULL DEFAULT 'summary',
                generated_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

function computeNextRun(schedule: string): string {
    const now = new Date();
    if (schedule === 'daily') now.setDate(now.getDate() + 1);
    else if (schedule === 'weekly') now.setDate(now.getDate() + 7);
    else now.setMonth(now.getMonth() + 1);
    return now.toISOString();
}

async function generateReport(scope: string, format: string, filters: Record<string, unknown>): Promise<string> {
    const dateRange = String(filters.dateRange || '7d');
    const interval = dateRange === '24h' ? '1 day' : dateRange === '30d' ? '30 days' : '7 days';
    const [iocStats, vulnStats, notifStats] = await Promise.all([
        rawQuery(sql.raw(`SELECT COUNT(*) AS total, COUNT(CASE WHEN severity = 'critical' THEN 1 END) AS critical FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}'`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total, COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) AS critical FROM vulnerabilities WHERE created_at >= NOW() - INTERVAL '${interval}'`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM notifications WHERE created_at >= NOW() - INTERVAL '${interval}'`)),
    ]);
    const ioc = iocStats.rows?.[0] as Record<string, unknown> || {};
    const vuln = vulnStats.rows?.[0] as Record<string, unknown> || {};
    const notif = notifStats.rows?.[0] as Record<string, unknown> || {};

    const title = `Threat Intelligence Report — ${dateRange} Summary`;
    const body = [
        `# ${title}`,
        `**Period:** Last ${dateRange} | **Generated:** ${new Date().toISOString()}`,
        '',
        '## Key Metrics',
        `| Metric | Count |`,
        `|--------|-------|`,
        `| New IOCs | ${ioc.total || 0} |`,
        `| Critical IOCs | ${ioc.critical || 0} |`,
        `| New Vulnerabilities | ${vuln.total || 0} |`,
        `| Critical CVEs | ${vuln.critical || 0} |`,
        `| Notifications | ${notif.total || 0} |`,
    ];

    if (scope !== 'summary') {
        const topIOCs = await rawQuery(sql.raw(`SELECT value, type, risk_score, source FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}' ORDER BY risk_score DESC LIMIT 10`));
        body.push('', '## Top Risk IOCs');
        for (const row of (topIOCs.rows || []) as Array<Record<string, unknown>>) {
            body.push(`- **${row.value}** (${row.type}) — Score: ${row.risk_score}, Source: ${row.source}`);
        }
    }

    if (scope === 'full') {
        const topVulns = await rawQuery(sql.raw(`SELECT cve_id, severity, description FROM vulnerabilities WHERE created_at >= NOW() - INTERVAL '${interval}' ORDER BY severity DESC LIMIT 10`));
        body.push('', '## Recent Critical Vulnerabilities');
        for (const row of (topVulns.rows || []) as Array<Record<string, unknown>>) {
            body.push(`- **${row.cve_id}** [${row.severity}] — ${String(row.description || '').slice(0, 120)}`);
        }
    }

    const md = body.join('\n');
    if (format === 'html') {
        return `<!DOCTYPE html><html><head><title>${title}</title></head><body><pre>${md}</pre></body></html>`;
    }
    return md;
}

// POST /reports/schedules
router.post('/reports/schedules', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const body = CreateReportScheduleSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const nextRun = computeNextRun(body.schedule);
    const result = await rawQuery(sql.raw(`
        INSERT INTO report_schedules (name, schedule, format, scope, filters, delivery, enabled, next_run_at, owner_id)
        VALUES ('${esc(body.name)}', '${esc(body.schedule)}', '${esc(body.format)}', '${esc(body.scope)}',
                '${JSON.stringify(body.filters).replace(/'/g, "''")}'::jsonb,
                '${JSON.stringify(body.delivery).replace(/'/g, "''")}'::jsonb,
                ${body.enabled}, '${esc(nextRun)}', '${esc(userId)}')
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// GET /reports/schedules
router.get('/reports/schedules', async (c) => {
    await ensureOnce();
    const result = await rawQuery(sql.raw(`SELECT * FROM report_schedules ORDER BY created_at DESC`));
    return c.json({ success: true, data: result.rows || [] });
});

// GET /reports/schedules/:id
router.get('/reports/schedules/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const [schedule, history] = await Promise.all([
        rawQuery(sql.raw(`SELECT * FROM report_schedules WHERE id = '${esc(id)}'`)),
        rawQuery(sql.raw(`SELECT id, name, format, scope, created_at FROM generated_reports WHERE schedule_id = '${esc(id)}' ORDER BY created_at DESC LIMIT 20`)),
    ]);
    if (!schedule.rows?.[0]) throw new NotFoundError('ReportSchedule', id);
    return c.json({ success: true, data: { ...schedule.rows[0], history: history.rows || [] } });
});

// PUT /reports/schedules/:id
router.put('/reports/schedules/:id', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = UpdateReportScheduleSchema.parse(await c.req.json().catch(() => ({})));
    const sets: string[] = ['updated_at = NOW()'];
    if (body.name) sets.push(`name = '${esc(body.name)}'`);
    if (body.schedule) { sets.push(`schedule = '${esc(body.schedule)}'`); sets.push(`next_run_at = '${esc(computeNextRun(body.schedule))}'`); }
    if (body.format) sets.push(`format = '${esc(body.format)}'`);
    if (body.scope) sets.push(`scope = '${esc(body.scope)}'`);
    if (body.filters) sets.push(`filters = '${JSON.stringify(body.filters).replace(/'/g, "''")}'::jsonb`);
    if (body.delivery) sets.push(`delivery = '${JSON.stringify(body.delivery).replace(/'/g, "''")}'::jsonb`);
    if (body.enabled !== undefined) sets.push(`enabled = ${body.enabled}`);
    const result = await rawQuery(sql.raw(`UPDATE report_schedules SET ${sets.join(', ')} WHERE id = '${esc(id)}' RETURNING *`));
    if (!result.rows?.[0]) throw new NotFoundError('ReportSchedule', id);
    return c.json({ success: true, data: result.rows[0] });
});

// DELETE /reports/schedules/:id
router.delete('/reports/schedules/:id', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM report_schedules WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('ReportSchedule', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// POST /reports/schedules/:id/run — Trigger immediate generation
router.post('/reports/schedules/:id/run', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const userId = c.get('user')?.id || 'unknown';
    const schedule = await rawQuery(sql.raw(`SELECT * FROM report_schedules WHERE id = '${esc(id)}'`));
    const sched = schedule.rows?.[0] as Record<string, unknown>;
    if (!sched) throw new NotFoundError('ReportSchedule', id);

    const content = await generateReport(
        String(sched.scope), String(sched.format),
        (sched.filters as Record<string, unknown>) || {},
    );

    const report = await rawQuery(sql.raw(`
        INSERT INTO generated_reports (schedule_id, name, format, content, scope, generated_by)
        VALUES ('${esc(id)}', '${esc(String(sched.name))}', '${esc(String(sched.format))}',
                '${esc(content)}', '${esc(String(sched.scope))}', '${esc(userId)}')
        RETURNING *
    `));

    await rawQuery(sql.raw(`UPDATE report_schedules SET last_run_at = NOW(), next_run_at = '${esc(computeNextRun(String(sched.schedule)))}' WHERE id = '${esc(id)}'`));
    log.info('Report generated', { scheduleId: id, reportId: (report.rows?.[0] as Record<string, unknown>)?.id });
    return c.json({ success: true, data: report.rows?.[0] }, 201);
});

// GET /reports/generated
router.get('/reports/generated', async (c) => {
    await ensureOnce();
    const limit = Math.min(parseInt(c.req.query('limit') || '20', 10), 100);
    const result = await rawQuery(sql.raw(`SELECT id, schedule_id, name, format, scope, generated_by, created_at FROM generated_reports ORDER BY created_at DESC LIMIT ${limit}`));
    return c.json({ success: true, data: result.rows || [] });
});

// GET /reports/generated/:id
router.get('/reports/generated/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`SELECT * FROM generated_reports WHERE id = '${esc(id)}'`));
    if (!result.rows?.[0]) throw new NotFoundError('GeneratedReport', id);
    return c.json({ success: true, data: result.rows[0] });
});

export default router;
