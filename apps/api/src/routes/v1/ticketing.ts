/**
 * Ticketing routes (Phase 4 #6 scaffold).
 *
 *   POST   /v1/cases/:caseId/tickets        Open an external ticket linked to this case
 *   GET    /v1/cases/:caseId/tickets        List all ticket links for a case
 *   GET    /v1/tickets                      List ticket links (filterable)
 *   GET    /v1/tickets/:linkId              Detail
 *   POST   /v1/tickets/:linkId/refresh      Re-poll the vendor and update status/title/labels
 *   POST   /v1/tickets/:linkId/comment      Push a comment to the external ticket
 *
 * GitHub Issues is the only vendor wired today. `vendor: 'jira'`
 * returns 502 with "not implemented" until the JIRA client lands.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    TicketCreateSchema, TicketCommentSchema, TicketListFiltersSchema,
} from '../../lib/schemas';
import {
    createTicketForCase, refreshTicket, syncCommentToTicket,
    listTicketLinks, getTicketLink,
} from '../../services/ticketing';

const router = new Hono();

// ── List + detail ──────────────────────────────────────────────────

router.get('/cases/:caseId/tickets', requireAuth, async (c) => {
    const caseId = c.req.param('caseId')!;
    const f = TicketListFiltersSchema.parse({ ...c.req.query(), caseId });
    const { items, total } = await listTicketLinks({
        caseId: f.caseId,
        vendor: f.vendor,
        page: f.page,
        pageSize: f.pageSize,
    });
    return c.json({
        success: true,
        data: items,
        pagination: { page: f.page, pageSize: f.pageSize, total },
    });
});

router.get('/tickets', requireAuth, async (c) => {
    const f = TicketListFiltersSchema.parse(c.req.query());
    const { items, total } = await listTicketLinks({
        caseId: f.caseId,
        vendor: f.vendor,
        page: f.page,
        pageSize: f.pageSize,
    });
    return c.json({
        success: true,
        data: items,
        pagination: { page: f.page, pageSize: f.pageSize, total },
    });
});

router.get('/tickets/:linkId', requireAuth, async (c) => {
    const linkId = c.req.param('linkId')!;
    const row = await getTicketLink(linkId);
    if (!row) throw new NotFoundError('Ticket link', linkId);
    return c.json({ success: true, data: row });
});

// ── Mutations ──────────────────────────────────────────────────────

router.post('/cases/:caseId/tickets', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const caseId = c.req.param('caseId')!;
    const body = TicketCreateSchema.parse(await c.req.json());
    const outcome = await createTicketForCase({
        caseId,
        vendor: body.vendor,
        repo: body.repo,
        title: body.title,
        body: body.body,
        labels: body.labels,
    });
    return c.json({ success: outcome.created, data: outcome }, outcome.created ? 201 : 502);
});

router.post('/tickets/:linkId/refresh', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const linkId = c.req.param('linkId')!;
    const row = await refreshTicket(linkId);
    if (!row) throw new NotFoundError('Ticket link', linkId);
    return c.json({ success: true, data: row });
});

router.post('/tickets/:linkId/comment', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const linkId = c.req.param('linkId')!;
    const body = TicketCommentSchema.parse(await c.req.json());
    const result = await syncCommentToTicket(linkId, body.body);
    return c.json({ success: result.ok, data: result }, result.ok ? 200 : 502);
});

export default router;
