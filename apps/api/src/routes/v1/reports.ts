/**
 * Report ingestion routes (Phase 3 #1 scaffold).
 *
 *   POST /v1/reports/ingest-text   Operator-pasted free-form text →
 *                                  draft (IOCs + LLM entities) for review
 *
 * PDF upload and URL fetch + readability are intentionally out of scope
 * for this PR — follow-ons. The text endpoint exists to validate the
 * end-to-end pipeline + return shape with no external dependencies
 * beyond an optional LLM provider.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { ReportIngestTextSchema } from '../../lib/schemas';
import { ingestReportText } from '../../services/reportIngestion';

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

export default router;
