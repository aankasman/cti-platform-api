/**
 * Inbound GitHub webhook handler — Phase 4 #6b.
 *
 * Closes the bidirectional sync loop: when an issue closes / reopens
 * in GitHub, the linked `ticket_links.status` flips automatically so
 * dashboards reflect external workflow without manual /refresh calls.
 *
 * GitHub signs every delivery with HMAC-SHA256 over the raw body
 * using the secret you configured in the webhook settings. The header
 * is `X-Hub-Signature-256: sha256=<hex>`. We compare in constant time.
 *
 * Without `GITHUB_WEBHOOK_SECRET` configured the route returns 503 —
 * we refuse to process unauthenticated payloads even in dev, since
 * the route is internet-exposed by design.
 *
 * Event support (initial scope — keep narrow):
 *   - `issues` event with action `closed` | `reopened` | `edited`
 *   - Anything else is acknowledged as a no-op (HTTP 200, kind:
 *     'ignored') so GitHub doesn't retry-storm.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { db, and, eq } from '@rinjani/db';
import { ticketLinks } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';

const log = createLogger('GHWebhook');

export type WebhookOutcome =
    | { kind: 'updated'; linkId: string; status: 'open' | 'closed' | 'unknown'; titleChanged: boolean }
    | { kind: 'ignored'; reason: string }
    | { kind: 'no_link'; vendorRepo: string; vendorIssueId: string };

/**
 * Constant-time signature check. Returns false on any structural
 * problem (missing header, malformed prefix, length mismatch) so a
 * malformed request never falls through to the success path.
 */
export function verifyGithubSignature(
    rawBody: string,
    signatureHeader: string | undefined,
    secret: string,
): boolean {
    if (!signatureHeader || !signatureHeader.startsWith('sha256=')) return false;
    const provided = signatureHeader.slice('sha256='.length);
    const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
    // timingSafeEqual throws on length mismatch — guard up front.
    if (provided.length !== expected.length) return false;
    return timingSafeEqual(Buffer.from(provided, 'hex'), Buffer.from(expected, 'hex'));
}

interface GithubIssuesPayload {
    action?: string;
    issue?: {
        number?: number;
        title?: string;
        state?: string;
        html_url?: string;
    };
    repository?: {
        full_name?: string;
    };
}

/**
 * Map a GitHub `issues` event action to our normalised TicketStatus.
 * `edited` retains the existing state — we only refresh the title.
 */
function statusFromAction(action: string, issueState?: string): 'open' | 'closed' | 'unknown' | null {
    if (action === 'closed') return 'closed';
    if (action === 'reopened') return 'open';
    if (action === 'edited') {
        // `edited` doesn't imply a state transition. Use the issue state if present so we still self-heal.
        if (issueState === 'closed') return 'closed';
        if (issueState === 'open') return 'open';
        return null; // title-only edit
    }
    return null;
}

/**
 * Apply a parsed payload. Returns a structured outcome so the route
 * can shape the response + the test can assert on the path taken.
 *
 * Only `issues` events are acted on. Other event types (push, star,
 * etc.) are acknowledged and ignored — GitHub sends many event types
 * to a single webhook URL and we want them all to 200 fast.
 */
export async function applyGithubWebhook(
    eventType: string,
    payload: GithubIssuesPayload,
): Promise<WebhookOutcome> {
    if (eventType !== 'issues') {
        return { kind: 'ignored', reason: `event=${eventType} not handled` };
    }

    const action = payload.action ?? '';
    const issue = payload.issue;
    const repo = payload.repository?.full_name;

    if (!issue?.number || !repo) {
        return { kind: 'ignored', reason: 'payload missing issue.number or repository.full_name' };
    }

    const targetStatus = statusFromAction(action, issue.state);
    const titleChanged = action === 'edited' && !!issue.title;

    if (!targetStatus && !titleChanged) {
        return { kind: 'ignored', reason: `action=${action} not handled` };
    }

    const vendorIssueId = String(issue.number);
    const [row] = await db
        .select()
        .from(ticketLinks)
        .where(and(
            eq(ticketLinks.vendor, 'github'),
            eq(ticketLinks.vendorRepo, repo),
            eq(ticketLinks.vendorIssueId, vendorIssueId),
        ))
        .limit(1);

    if (!row) {
        // Webhook fires for issues we don't track — completely normal
        // when a repo is shared with non-CTI work. Acknowledge so
        // GitHub doesn't keep retrying.
        return { kind: 'no_link', vendorRepo: repo, vendorIssueId };
    }

    const patch: Record<string, unknown> = {
        lastSyncedAt: new Date(),
        lastSyncError: null,
        updatedAt: new Date(),
    };
    if (targetStatus) patch.status = targetStatus;
    if (titleChanged && issue.title) patch.title = issue.title;

    await db.update(ticketLinks).set(patch).where(eq(ticketLinks.id, row.id));

    log.info('webhook applied', {
        linkId: row.id, action, targetStatus, titleChanged, repo, issueNumber: issue.number,
    });

    return {
        kind: 'updated',
        linkId: row.id,
        status: targetStatus ?? (row.status as 'open' | 'closed' | 'unknown'),
        titleChanged,
    };
}
