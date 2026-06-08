/**
 * Sandbox umbrella service.
 *
 * Vendor-agnostic facade over the per-vendor clients (currently only
 * ANY.RUN; Joe Sandbox + Hybrid Analysis are stubs that report
 * "not configured" until their clients land in follow-up PRs).
 *
 * Storage:
 *   - `sandbox_reports` row created at submission with status='queued'
 *   - Same row updated when the caller polls via `refreshSandboxReport`
 */
import { db, eq, desc, and, sql } from '@rinjani/db';
import {
    sandboxReports,
    type SandboxReport, type SandboxVendor, type SandboxSubmissionType,
} from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import { anyRunSubmit, anyRunGetReport } from './anyrun';

const log = createLogger('Sandbox');

export interface SubmitInput {
    vendor: SandboxVendor;
    value: string;
    type: SandboxSubmissionType;
    iocId?: string | null;
    options?: Record<string, unknown>;
}

export interface SubmitOutcome {
    report: SandboxReport;
    /** True iff the vendor accepted the submission. */
    submitted: boolean;
    error?: string;
}

/** Submit a value to a sandbox vendor and create the tracking row. */
export async function submitForAnalysis(input: SubmitInput): Promise<SubmitOutcome> {
    const [row] = await db.insert(sandboxReports).values({
        vendor: input.vendor,
        submittedIocId: input.iocId ?? null,
        submittedValue: input.value,
        submittedType: input.type,
        status: 'queued',
    }).returning();

    const vendorRes = await dispatchSubmit(input);
    if (!vendorRes.ok) {
        const [failed] = await db.update(sandboxReports)
            .set({ status: 'failed', error: vendorRes.error ?? 'submit failed', updatedAt: new Date() })
            .where(eq(sandboxReports.id, row.id))
            .returning();
        log.warn('sandbox submit failed', { vendor: input.vendor, error: vendorRes.error });
        return { report: failed, submitted: false, error: vendorRes.error };
    }

    const [updated] = await db.update(sandboxReports)
        .set({
            vendorTaskId: vendorRes.taskId,
            reportUrl: vendorRes.reportUrl,
            status: 'running',
            updatedAt: new Date(),
        })
        .where(eq(sandboxReports.id, row.id))
        .returning();

    log.info('sandbox submitted', { id: updated.id, vendor: input.vendor, taskId: vendorRes.taskId });
    return { report: updated, submitted: true };
}

async function dispatchSubmit(input: SubmitInput): Promise<{ ok: boolean; taskId?: string; reportUrl?: string; error?: string }> {
    switch (input.vendor) {
        case 'anyrun':
            return anyRunSubmit({ value: input.value, type: input.type, options: input.options });
        case 'joesandbox':
        case 'hybridanalysis':
            return { ok: false, error: `${input.vendor} client not yet implemented (scaffold ships ANY.RUN only)` };
    }
}

/** Re-fetch the vendor's report and update the row. */
export async function refreshSandboxReport(id: string): Promise<SandboxReport | null> {
    const [row] = await db.select().from(sandboxReports).where(eq(sandboxReports.id, id)).limit(1);
    if (!row) return null;
    if (!row.vendorTaskId) return row;
    if (row.status === 'completed' || row.status === 'failed') return row;

    const r = await (async () => {
        switch (row.vendor) {
            case 'anyrun': return anyRunGetReport(row.vendorTaskId!);
            default: return { ok: false, error: `${row.vendor} polling not implemented` };
        }
    })();

    if (!r.ok) {
        const [updated] = await db.update(sandboxReports)
            .set({ error: r.error, updatedAt: new Date() })
            .where(eq(sandboxReports.id, id))
            .returning();
        return updated;
    }

    const completing = r.status === 'completed';
    const [updated] = await db.update(sandboxReports)
        .set({
            status: r.status ?? row.status,
            verdict: r.verdict,
            score: r.score,
            reportUrl: r.reportUrl ?? row.reportUrl,
            reportJson: r.raw,
            completedAt: completing ? new Date() : row.completedAt,
            error: null,
            updatedAt: new Date(),
        })
        .where(eq(sandboxReports.id, id))
        .returning();

    log.info('sandbox refresh', { id, status: updated.status, verdict: updated.verdict });
    return updated;
}

export interface ListFilters {
    vendor?: SandboxVendor;
    status?: SandboxReport['status'];
    iocId?: string;
    page: number;
    pageSize: number;
}

export async function listSandboxReports(filters: ListFilters): Promise<{ items: SandboxReport[]; total: number }> {
    const conds = [];
    if (filters.vendor) conds.push(eq(sandboxReports.vendor, filters.vendor));
    if (filters.status) conds.push(eq(sandboxReports.status, filters.status));
    if (filters.iocId) conds.push(eq(sandboxReports.submittedIocId, filters.iocId));
    const where = conds.length === 0 ? undefined : (conds.length === 1 ? conds[0] : and(...conds));
    const offset = (filters.page - 1) * filters.pageSize;
    const [items, totals] = await Promise.all([
        db.select().from(sandboxReports).where(where ?? sql`true`).orderBy(desc(sandboxReports.submittedAt)).limit(filters.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(sandboxReports).where(where ?? sql`true`),
    ]);
    return { items, total: totals[0]?.c ?? 0 };
}

export async function getSandboxReport(id: string): Promise<SandboxReport | null> {
    const [row] = await db.select().from(sandboxReports).where(eq(sandboxReports.id, id)).limit(1);
    return row ?? null;
}
