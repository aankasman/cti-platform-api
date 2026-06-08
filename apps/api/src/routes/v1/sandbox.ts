/**
 * Sandbox submission + report management. Phase 4 #5 scaffold.
 *
 *   POST /v1/sandbox/submit            — submit a URL/hash to a sandbox
 *   GET  /v1/sandbox/reports           — list reports (filterable)
 *   GET  /v1/sandbox/reports/:id       — single report detail
 *   POST /v1/sandbox/reports/:id/refresh — poll the vendor for an update
 *
 * Only ANY.RUN is wired today; Joe Sandbox + Hybrid Analysis return
 * "not implemented" until their per-vendor clients land in follow-ups.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    SandboxSubmitSchema, SandboxListFiltersSchema,
} from '../../lib/schemas';
import {
    submitForAnalysis, listSandboxReports, getSandboxReport, refreshSandboxReport,
} from '../../services/sandbox';

const router = new Hono();

router.post('/sandbox/submit', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = SandboxSubmitSchema.parse(await c.req.json());
    const outcome = await submitForAnalysis({
        vendor: body.vendor,
        value: body.value,
        type: body.type,
        iocId: body.iocId ?? null,
        options: body.options ?? undefined,
    });
    // 502 when the vendor refused / wasn't configured — surfaces the
    // operator-side failure separately from a row-not-found NotFoundError.
    return c.json({ success: outcome.submitted, data: outcome }, outcome.submitted ? 201 : 502);
});

router.get('/sandbox/reports', requireAuth, async (c) => {
    const f = SandboxListFiltersSchema.parse(c.req.query());
    const { items, total } = await listSandboxReports({
        vendor: f.vendor,
        status: f.status,
        iocId: f.iocId,
        page: f.page,
        pageSize: f.pageSize,
    });
    return c.json({
        success: true,
        data: items,
        pagination: { page: f.page, pageSize: f.pageSize, total },
    });
});

router.get('/sandbox/reports/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const row = await getSandboxReport(id);
    if (!row) throw new NotFoundError('Sandbox report', id);
    return c.json({ success: true, data: row });
});

router.post('/sandbox/reports/:id/refresh', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const row = await refreshSandboxReport(id);
    if (!row) throw new NotFoundError('Sandbox report', id);
    return c.json({ success: true, data: row });
});

export default router;
