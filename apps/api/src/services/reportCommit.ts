/**
 * Commit operator-approved IOCs from a stored report draft into the
 * canonical `iocs` table — Phase 3 #1 follow-on.
 *
 * Honest scope:
 *   - IOCs only. The LLM-fuzzy entity strings (threat actor names,
 *     malware families, campaigns) need their own commit path that
 *     resolves to STIX entities by canonical name, with disambiguation
 *     for "lazarus" vs "Lazarus Group" vs "APT38" — that's a separate
 *     follow-up.
 *   - CVE drafts are also out of scope here. CVEs belong in the
 *     `vulnerabilities` table, not `iocs`; a future PR can wire those.
 *   - Confidence + severity default to safe-but-low values ("medium" /
 *     50) so a noisy report can't unilaterally elevate IOC priority.
 *     Operators tune those via the existing IOC edit route.
 *
 * Commit is idempotent against the IOC `value` unique constraint:
 * re-running the same approval set bumps `last_seen` but doesn't
 * duplicate. The summary distinguishes created vs updated vs skipped.
 */
import { db, eq, inArray, sql } from '@rinjani/db';
import { iocs, extractedReports } from '@rinjani/db/schema';
import type { ExtractedReport } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';
import type { IocKind, ExtractedIoc } from '@rinjani/core/iocExtractor';

const log = createLogger('ReportCommit');

/** Map the extractor's fine-grained kind into the IOC table's broader `type`. */
function kindToIocType(kind: IocKind): string | null {
    switch (kind) {
        case 'ipv4':
        case 'ipv6': return 'ip';
        case 'domain': return 'domain';
        case 'url': return 'url';
        case 'email': return 'email';
        case 'hash-md5':
        case 'hash-sha1':
        case 'hash-sha256': return 'hash';
        case 'cve': return null; // CVEs belong in `vulnerabilities`, not iocs
        default: return null;
    }
}

export interface CommitInput {
    reportId: string;
    /**
     * Subset of `(kind, value)` pairs the operator approved. Anything in the
     * draft but not in this list is skipped. An empty array commits nothing
     * (but transitions status to 'committed' with zero counts — same as a
     * dismiss except labelled differently).
     */
    approvedIocs: Array<{ kind: IocKind; value: string }>;
    committedBy: string;
    /**
     * Optional override for the IOC `source` column. Defaults to the report's
     * own `source` value, or `report-ingestion` if that's empty.
     */
    iocSource?: string;
}

export interface CommitSummary {
    reportId: string;
    iocs: {
        approved: number;
        created: number;
        updated: number;
        skipped: number;
        skippedReasons: Record<string, number>;
    };
    /** Names extracted but NOT committed — entity-commit lands in a follow-up. */
    entitiesDeferred: {
        threatActors: number;
        malwareFamilies: number;
        campaigns: number;
        vulnerabilities: number;
    };
}

export async function commitReport(input: CommitInput): Promise<CommitSummary> {
    // Fetch + validate the report.
    const [report] = await db.select().from(extractedReports).where(eq(extractedReports.id, input.reportId)).limit(1);
    if (!report) throw new Error(`report ${input.reportId} not found`);
    if (report.status !== 'draft') {
        throw new Error(`report ${input.reportId} is ${report.status}, can only commit drafts`);
    }

    const summary: CommitSummary = {
        reportId: input.reportId,
        iocs: {
            approved: input.approvedIocs.length,
            created: 0,
            updated: 0,
            skipped: 0,
            skippedReasons: {},
        },
        entitiesDeferred: countEntities(report),
    };

    if (input.approvedIocs.length === 0) {
        await markCommitted(input.reportId, input.committedBy, summary);
        return summary;
    }

    // Build the canonical draft index so we can look up the kind for each
    // approved (kind, value) pair and reject anything that wasn't actually
    // in the draft.
    const draftIndex = indexDraftIocs(report);
    const source = input.iocSource ?? report.source ?? 'report-ingestion';
    const now = new Date();

    // Drizzle's upsert: insert with onConflictDoUpdate. The `value` column is
    // unique so a duplicate-on-value re-bumps `last_seen` instead of throwing.
    for (const a of input.approvedIocs) {
        const key = `${a.kind}|${a.value}`;
        const draft = draftIndex.get(key);
        if (!draft) {
            summary.iocs.skipped++;
            summary.iocs.skippedReasons.not_in_draft = (summary.iocs.skippedReasons.not_in_draft ?? 0) + 1;
            continue;
        }
        const iocType = kindToIocType(a.kind);
        if (!iocType) {
            summary.iocs.skipped++;
            const reason = a.kind === 'cve' ? 'cve_belongs_in_vulnerabilities' : 'unknown_kind';
            summary.iocs.skippedReasons[reason] = (summary.iocs.skippedReasons[reason] ?? 0) + 1;
            continue;
        }

        try {
            const [row] = await db.insert(iocs).values({
                type: iocType,
                value: a.value,
                source,
                severity: 'medium',
                confidence: 50,
                threatType: null,
                firstSeen: now,
                lastSeen: now,
                rawData: { fromReportId: input.reportId, draftKind: a.kind },
            }).onConflictDoUpdate({
                target: iocs.value,
                set: {
                    lastSeen: now,
                    // Don't downgrade severity/confidence on re-import — preserve
                    // whatever the existing row has. Drizzle's `set` only writes
                    // these fields; everything else stays as-is.
                    rawData: sql`COALESCE(${iocs.rawData}, '{}'::jsonb) || ${{ lastReportId: input.reportId }}::jsonb`,
                },
            }).returning({ id: iocs.id, createdAt: iocs.createdAt });

            // Distinguish created vs updated by createdAt proximity to `now`.
            // Drizzle doesn't return an `(xmax = 0)` style "was-inserted" flag;
            // this approximation is good enough for the summary.
            const rowCreatedAt = row?.createdAt;
            if (rowCreatedAt && Math.abs(rowCreatedAt.getTime() - now.getTime()) < 2_000) {
                summary.iocs.created++;
            } else {
                summary.iocs.updated++;
            }
        } catch (err) {
            log.warn('IOC upsert failed', { kind: a.kind, value: a.value, error: (err as Error).message });
            summary.iocs.skipped++;
            summary.iocs.skippedReasons.upsert_error = (summary.iocs.skippedReasons.upsert_error ?? 0) + 1;
        }
    }

    await markCommitted(input.reportId, input.committedBy, summary);
    log.info('Report committed', {
        reportId: input.reportId,
        created: summary.iocs.created,
        updated: summary.iocs.updated,
        skipped: summary.iocs.skipped,
    });
    return summary;
}

/**
 * Mark the report as dismissed without committing anything. Same lifecycle
 * end as `commitReport({approvedIocs: []})` but labelled as a dismissal so
 * the audit trail shows operator intent.
 */
export async function dismissReport(reportId: string, dismissedBy: string): Promise<void> {
    await db.update(extractedReports)
        .set({
            status: 'dismissed',
            committedAt: new Date(),
            committedBy: dismissedBy,
            commitSummary: { dismissed: true },
        })
        .where(eq(extractedReports.id, reportId));
    log.info('Report dismissed', { reportId, dismissedBy });
}

// ── Internals ──────────────────────────────────────────────────────

interface DraftIocsShape { items?: ExtractedIoc[] }
interface DraftEntitiesShape {
    threatActors?: string[];
    malwareFamilies?: string[];
    campaigns?: string[];
    vulnerabilities?: string[];
}

function indexDraftIocs(report: ExtractedReport): Map<string, ExtractedIoc> {
    const idx = new Map<string, ExtractedIoc>();
    const draftItems = (report.iocs as DraftIocsShape).items ?? [];
    for (const item of draftItems) idx.set(`${item.kind}|${item.value}`, item);
    return idx;
}

function countEntities(report: ExtractedReport): CommitSummary['entitiesDeferred'] {
    const e = (report.entities as DraftEntitiesShape) ?? {};
    return {
        threatActors: e.threatActors?.length ?? 0,
        malwareFamilies: e.malwareFamilies?.length ?? 0,
        campaigns: e.campaigns?.length ?? 0,
        vulnerabilities: e.vulnerabilities?.length ?? 0,
    };
}

async function markCommitted(reportId: string, committedBy: string, summary: CommitSummary): Promise<void> {
    await db.update(extractedReports)
        .set({
            status: 'committed',
            committedAt: new Date(),
            committedBy,
            commitSummary: summary as unknown as Record<string, unknown>,
        })
        .where(eq(extractedReports.id, reportId));
}

// Suppress unused-import warning — the `inArray` helper is kept for the
// follow-on entity-commit path that batch-resolves names → STIX rows.
export const _reserved = { inArray };
