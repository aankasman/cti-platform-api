/**
 * Ticketing umbrella service.
 *
 * Vendor-agnostic facade over the per-vendor clients (GitHub today;
 * JIRA stubbed as "not implemented" until its client lands).
 *
 * Lifecycle:
 *   - createTicketForCase  → fetches the case, asks the vendor to open
 *                            an issue, persists the link row
 *   - refreshTicket        → re-queries the vendor, updates status +
 *                            title + labels + last_synced_at on the row
 *   - syncCommentToTicket  → pushes a comment to the external ticket
 *   - listLinksForCase     → dashboard helper
 */
import { db, eq, desc, and, sql, rawQuery } from '@rinjani/db';
import {
    ticketLinks,
    type TicketLink, type TicketVendor,
} from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import { ghCreateIssue, ghGetIssue, ghAddComment } from './github';

const log = createLogger('Ticketing');

export interface CreateInput {
    caseId: string;
    vendor: TicketVendor;
    repo: string;
    /** Override the issue title. Defaults to the case title. */
    title?: string;
    /** Override the issue body. Defaults to the case description + a link back to the case. */
    body?: string;
    labels?: string[];
}

export interface CreateOutcome {
    link: TicketLink;
    created: boolean;
    error?: string;
}

interface CaseRow extends Record<string, unknown> {
    id: string;
    title: string;
    description: string | null;
    severity: string | null;
    status: string | null;
}

async function getCase(caseId: string): Promise<CaseRow | null> {
    const r = await rawQuery<CaseRow>(sql.raw(`
        SELECT id, title, description, severity, status
        FROM cases
        WHERE id = '${caseId.replace(/'/g, "''")}'
        LIMIT 1
    `));
    return r.rows?.[0] ?? null;
}

function defaultBody(c: CaseRow): string {
    const sev = c.severity ? ` (severity: ${c.severity})` : '';
    return [
        c.description?.trim() || '_(case has no description)_',
        '',
        '---',
        `Linked from Rinjani CTI case \`${c.id}\`${sev}.`,
    ].join('\n');
}

export async function createTicketForCase(input: CreateInput): Promise<CreateOutcome> {
    const c = await getCase(input.caseId);
    if (!c) throw new Error(`case ${input.caseId} not found`);

    const title = input.title ?? c.title;
    const body = input.body ?? defaultBody(c);

    let vendorRes: { ok: boolean; issueNumber?: number; issueUrl?: string; error?: string };
    switch (input.vendor) {
        case 'github':
            vendorRes = await ghCreateIssue({ repo: input.repo, title, body, labels: input.labels });
            break;
        case 'jira':
            return {
                link: {} as TicketLink,
                created: false,
                error: 'jira client not yet implemented (scaffold ships GitHub Issues only)',
            };
    }

    if (!vendorRes.ok || !vendorRes.issueNumber || !vendorRes.issueUrl) {
        // No row written: surface the error to the caller.
        log.warn('ticket create failed', { vendor: input.vendor, repo: input.repo, error: vendorRes.error });
        return { link: {} as TicketLink, created: false, error: vendorRes.error ?? 'create failed' };
    }

    const [row] = await db.insert(ticketLinks).values({
        caseId: input.caseId,
        vendor: input.vendor,
        vendorRepo: input.repo,
        vendorIssueId: String(vendorRes.issueNumber),
        vendorIssueUrl: vendorRes.issueUrl,
        title,
        status: 'open',
        labels: input.labels ?? [],
        lastSyncedAt: new Date(),
    }).returning();

    log.info('ticket created', { linkId: row.id, vendor: input.vendor, repo: input.repo, issueNumber: vendorRes.issueNumber });
    return { link: row, created: true };
}

export async function refreshTicket(linkId: string): Promise<TicketLink | null> {
    const [row] = await db.select().from(ticketLinks).where(eq(ticketLinks.id, linkId)).limit(1);
    if (!row) return null;

    let r: { ok: boolean; status?: string; title?: string; labels?: string[]; error?: string };
    switch (row.vendor) {
        case 'github':
            r = await ghGetIssue({ repo: row.vendorRepo, issueNumber: row.vendorIssueId });
            break;
        default:
            r = { ok: false, error: `${row.vendor} polling not implemented` };
    }

    if (!r.ok) {
        const [updated] = await db.update(ticketLinks)
            .set({ lastSyncError: r.error, updatedAt: new Date() })
            .where(eq(ticketLinks.id, linkId))
            .returning();
        return updated;
    }

    const [updated] = await db.update(ticketLinks)
        .set({
            status: (r.status ?? row.status) as TicketLink['status'],
            title: r.title ?? row.title,
            labels: r.labels ?? row.labels,
            lastSyncedAt: new Date(),
            lastSyncError: null,
            updatedAt: new Date(),
        })
        .where(eq(ticketLinks.id, linkId))
        .returning();

    log.info('ticket refreshed', { linkId, status: updated.status });
    return updated;
}

export async function syncCommentToTicket(linkId: string, body: string): Promise<{ ok: boolean; commentUrl?: string; error?: string }> {
    const [row] = await db.select().from(ticketLinks).where(eq(ticketLinks.id, linkId)).limit(1);
    if (!row) return { ok: false, error: `ticket link ${linkId} not found` };

    switch (row.vendor) {
        case 'github':
            return ghAddComment({ repo: row.vendorRepo, issueNumber: row.vendorIssueId, body });
        default:
            return { ok: false, error: `${row.vendor} comment sync not implemented` };
    }
}

export interface ListFilters {
    caseId?: string;
    vendor?: TicketVendor;
    page: number;
    pageSize: number;
}

export async function listTicketLinks(filters: ListFilters): Promise<{ items: TicketLink[]; total: number }> {
    const conds = [];
    if (filters.caseId) conds.push(eq(ticketLinks.caseId, filters.caseId));
    if (filters.vendor) conds.push(eq(ticketLinks.vendor, filters.vendor));
    const where = conds.length === 0 ? undefined : (conds.length === 1 ? conds[0] : and(...conds));
    const offset = (filters.page - 1) * filters.pageSize;
    const [items, totals] = await Promise.all([
        db.select().from(ticketLinks).where(where ?? sql`true`).orderBy(desc(ticketLinks.createdAt)).limit(filters.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(ticketLinks).where(where ?? sql`true`),
    ]);
    return { items, total: totals[0]?.c ?? 0 };
}

export async function getTicketLink(linkId: string): Promise<TicketLink | null> {
    const [row] = await db.select().from(ticketLinks).where(eq(ticketLinks.id, linkId)).limit(1);
    return row ?? null;
}
