/**
 * Report ingestion routes (Phase 3 #1).
 *
 *   POST /v1/reports/ingest-text   Operator-pasted free-form text
 *   POST /v1/reports/ingest-url    Fetch + readability-extract a URL
 *   POST /v1/reports/ingest-pdf    Multipart upload of a PDF
 *   GET  /v1/reports                List persisted drafts (filterable)
 *   GET  /v1/reports/:id            Retrieve a stored draft
 *   POST /v1/reports/:id/commit     Apply approved IOCs to the iocs table
 *   POST /v1/reports/:id/dismiss    Mark a draft as dismissed without committing
 *
 * All three input shapes share the same downstream pipeline: convert
 * to plain text → run deterministic IOC extraction + LLM entity
 * enrichment → persist a draft → return it. Operator reviews the
 * draft via GET, then commits a subset of IOCs via /commit (or
 * /dismiss to end the lifecycle without import).
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    ReportIngestTextSchema, ReportIngestUrlSchema,
    ReportCommitSchema, ReportListSchema,
} from '../../lib/schemas';
import { ingestReportText } from '../../services/reportIngestion';
import { commitReport, dismissReport } from '../../services/reportCommit';
import { extractFromPdfBuffer, extractFromUrl } from '../../services/reportSources';
import { createLogger } from '../../lib/logger';
import { db, eq, desc, and, sql } from '@rinjani/db';
import { extractedReports } from '@rinjani/db/schema';

const log = createLogger('ReportRoutes');
const router = new Hono();

// ── Ingestion ──────────────────────────────────────────────────────

router.post('/reports/ingest-text', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = ReportIngestTextSchema.parse(await c.req.json());
    const userId = c.get('user')?.id || 'unknown';
    const draft = await ingestReportText({
        text: body.text,
        source: body.source,
        sourceKind: 'text',
        provider: body.provider,
        skipLlm: body.skipLlm,
        createdBy: userId,
    });
    return c.json({ success: true, data: draft });
});

router.post('/reports/ingest-url', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = ReportIngestUrlSchema.parse(await c.req.json());
    const userId = c.get('user')?.id || 'unknown';

    let extraction;
    try {
        extraction = await extractFromUrl(body.url);
    } catch (err) {
        const msg = (err as Error).message;
        log.warn('URL extraction failed', { url: body.url, error: msg });
        return c.json({ success: false, error: { code: 'URL_FETCH_FAILED', message: msg } }, 502);
    }

    const sourceMeta = {
        kind: 'url',
        finalUrl: extraction.finalUrl,
        title: extraction.title,
        contentType: extraction.contentType,
        bytes: extraction.bytes,
    };

    const draft = await ingestReportText({
        text: extraction.text,
        source: body.source ?? extraction.finalUrl,
        sourceKind: 'url',
        sourceMeta,
        provider: body.provider,
        skipLlm: body.skipLlm,
        createdBy: userId,
    });

    return c.json({ success: true, data: { ...draft, sourceMeta } });
});

router.post('/reports/ingest-pdf', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    // multipart with a `file` field — same upload shape as /v1/yara/scan-sample.
    const form = await c.req.parseBody().catch(() => null);
    if (!form) {
        return c.json({ success: false, error: { code: 'BAD_REQUEST', message: 'multipart/form-data with a `file` field required' } }, 400);
    }
    const file = (form as Record<string, unknown>).file;
    if (!(file instanceof Blob)) {
        return c.json({ success: false, error: { code: 'BAD_REQUEST', message: 'missing `file` field' } }, 400);
    }

    const filename = (file as File).name || 'upload.pdf';
    const source = (typeof (form as Record<string, unknown>).source === 'string'
        ? (form as Record<string, unknown>).source as string
        : undefined) ?? filename;
    const skipLlm = (form as Record<string, unknown>).skipLlm === 'true';
    const providerRaw = (form as Record<string, unknown>).provider;
    const provider = typeof providerRaw === 'string' &&
        ['gemini', 'openrouter', 'ollama'].includes(providerRaw)
        ? providerRaw as 'gemini' | 'openrouter' | 'ollama'
        : undefined;

    const buf = Buffer.from(await file.arrayBuffer());
    const userId = c.get('user')?.id || 'unknown';

    let extraction;
    try {
        extraction = await extractFromPdfBuffer(buf);
    } catch (err) {
        const msg = (err as Error).message;
        log.warn('PDF extraction failed', { filename, error: msg });
        return c.json({ success: false, error: { code: 'PDF_PARSE_FAILED', message: msg } }, 400);
    }

    const sourceMeta = {
        kind: 'pdf',
        filename,
        pageCount: extraction.pageCount,
        title: extraction.title,
        bytes: buf.length,
    };

    const draft = await ingestReportText({
        text: extraction.text,
        source,
        sourceKind: 'pdf',
        sourceMeta,
        provider,
        skipLlm,
        createdBy: userId,
    });

    return c.json({ success: true, data: { ...draft, sourceMeta } });
});

// ── List + retrieve ────────────────────────────────────────────────

router.get('/reports', requireAuth, async (c) => {
    const f = ReportListSchema.parse(c.req.query());
    const where = f.status ? eq(extractedReports.status, f.status) : undefined;
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select({
            id: extractedReports.id,
            source: extractedReports.source,
            sourceKind: extractedReports.sourceKind,
            status: extractedReports.status,
            textLength: extractedReports.textLength,
            extractedAt: extractedReports.extractedAt,
            createdAt: extractedReports.createdAt,
            createdBy: extractedReports.createdBy,
            committedAt: extractedReports.committedAt,
            committedBy: extractedReports.committedBy,
        }).from(extractedReports)
            .where(where ?? sql`true`)
            .orderBy(desc(extractedReports.createdAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` })
            .from(extractedReports)
            .where(where ?? sql`true`),
    ]);

    return c.json({
        success: true,
        data: items,
        pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
    });
});

router.get('/reports/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const [row] = await db.select().from(extractedReports).where(eq(extractedReports.id, id)).limit(1);
    if (!row) throw new NotFoundError('Extracted report', id);
    return c.json({ success: true, data: row });
});

// ── Commit + dismiss ───────────────────────────────────────────────

router.post('/reports/:id/commit', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = ReportCommitSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    try {
        const summary = await commitReport({
            reportId: id,
            approvedIocs: body.approvedIocs,
            committedBy: userId,
            iocSource: body.iocSource,
        });
        return c.json({ success: true, data: summary });
    } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes('not found')) throw new NotFoundError('Extracted report', id);
        if (msg.includes('can only commit drafts')) {
            return c.json({ success: false, error: { code: 'ALREADY_COMMITTED', message: msg } }, 409);
        }
        throw err;
    }
});

router.post('/reports/:id/dismiss', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const [exists] = await db.select({ id: extractedReports.id, status: extractedReports.status })
        .from(extractedReports).where(eq(extractedReports.id, id)).limit(1);
    if (!exists) throw new NotFoundError('Extracted report', id);
    if (exists.status !== 'draft') {
        return c.json({ success: false, error: { code: 'ALREADY_COMMITTED', message: `report is ${exists.status}` } }, 409);
    }
    const userId = c.get('user')?.id || 'unknown';
    await dismissReport(id, userId);
    return c.json({ success: true, data: { id, status: 'dismissed' } });
});

// Suppress unused-import warning until the follow-on lands the multi-status filter.
export const _reserved = { and };

export default router;
