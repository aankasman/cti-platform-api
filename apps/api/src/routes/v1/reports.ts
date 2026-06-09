/**
 * Report ingestion routes (Phase 3 #1).
 *
 *   POST /v1/reports/ingest-text   Operator-pasted free-form text
 *   POST /v1/reports/ingest-url    Fetch + readability-extract a URL
 *   POST /v1/reports/ingest-pdf    Multipart upload of a PDF
 *
 * All three share the same downstream pipeline: convert input to plain
 * text → run deterministic IOC extraction + LLM entity enrichment →
 * return a draft for operator review.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { ReportIngestTextSchema, ReportIngestUrlSchema } from '../../lib/schemas';
import { ingestReportText } from '../../services/reportIngestion';
import { extractFromPdfBuffer, extractFromUrl } from '../../services/reportSources';
import { createLogger } from '../../lib/logger';

const log = createLogger('ReportRoutes');
const router = new Hono();

router.post('/reports/ingest-text', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = ReportIngestTextSchema.parse(await c.req.json());
    const draft = await ingestReportText({
        text: body.text,
        source: body.source,
        provider: body.provider,
        skipLlm: body.skipLlm,
    });
    return c.json({ success: true, data: draft });
});

router.post('/reports/ingest-url', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = ReportIngestUrlSchema.parse(await c.req.json());

    let extraction;
    try {
        extraction = await extractFromUrl(body.url);
    } catch (err) {
        const msg = (err as Error).message;
        log.warn('URL extraction failed', { url: body.url, error: msg });
        return c.json({ success: false, error: { code: 'URL_FETCH_FAILED', message: msg } }, 502);
    }

    const draft = await ingestReportText({
        text: extraction.text,
        source: body.source ?? extraction.finalUrl,
        provider: body.provider,
        skipLlm: body.skipLlm,
    });

    return c.json({
        success: true,
        data: {
            ...draft,
            sourceMeta: {
                kind: 'url',
                finalUrl: extraction.finalUrl,
                title: extraction.title,
                contentType: extraction.contentType,
                bytes: extraction.bytes,
            },
        },
    });
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
    // Default source attribution to the operator-provided value, falling back
    // to the uploaded filename — useful provenance in the dashboard later.
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

    let extraction;
    try {
        extraction = await extractFromPdfBuffer(buf);
    } catch (err) {
        const msg = (err as Error).message;
        log.warn('PDF extraction failed', { filename, error: msg });
        return c.json({ success: false, error: { code: 'PDF_PARSE_FAILED', message: msg } }, 400);
    }

    const draft = await ingestReportText({
        text: extraction.text,
        source,
        provider,
        skipLlm,
    });

    return c.json({
        success: true,
        data: {
            ...draft,
            sourceMeta: {
                kind: 'pdf',
                filename,
                pageCount: extraction.pageCount,
                title: extraction.title,
                bytes: buf.length,
            },
        },
    });
});

export default router;
