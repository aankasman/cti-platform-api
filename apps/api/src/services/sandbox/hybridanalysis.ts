/**
 * Hybrid Analysis (Falcon Sandbox) client. Phase 4 #5 follow-on.
 *
 * API: https://www.hybrid-analysis.com/docs/api/v2
 *   POST /api/v2/submit/url        → submit a URL for full analysis (returns job_id)
 *   GET  /api/v2/report/{id}/state → polling-friendly state probe
 *   GET  /api/v2/report/{id}/summary → final report once IN_PROGRESS → SUCCESS
 *
 * Auth: `api-key` request header. Hybrid Analysis additionally requires
 * a User-Agent header — they reject the request otherwise.
 */
import { createLogger } from '../../lib/logger';
import type { SandboxSubmissionType } from '@rinjani/db/schema';

const log = createLogger('HybridAnalysis');

const HA_BASE = 'https://www.hybrid-analysis.com/api/v2';
const HA_UA = 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)';
// Falcon Sandbox environment id — 100=Win7x64 (default for the free tier).
const HA_DEFAULT_ENV = process.env.HYBRIDANALYSIS_ENV_ID ?? '100';

export interface HASubmitInput {
    value: string;
    type: SandboxSubmissionType;
    options?: Record<string, unknown>;
}
export interface HASubmitResult { ok: boolean; taskId?: string; reportUrl?: string; error?: string }
export interface HAReportResult {
    ok: boolean;
    status?: 'queued' | 'running' | 'completed' | 'failed' | 'timeout';
    verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown';
    score?: number;
    reportUrl?: string;
    raw?: Record<string, unknown>;
    error?: string;
}

function getApiKey(): string | null {
    return process.env.HYBRIDANALYSIS_API_KEY?.trim() || null;
}

function authHeaders(key: string): Record<string, string> {
    return {
        'api-key': key,
        'User-Agent': HA_UA,
        'Accept': 'application/json',
    };
}

export async function haSubmit(input: HASubmitInput): Promise<HASubmitResult> {
    const key = getApiKey();
    if (!key) return { ok: false, error: 'HYBRIDANALYSIS_API_KEY not configured' };

    if (input.type !== 'url') {
        // Hash + file submissions need different endpoints (/search/hash for
        // lookup, /submit/file for upload). Wire them in a follow-up.
        return { ok: false, error: `submission type "${input.type}" not yet supported by the Hybrid Analysis client` };
    }

    const form = new FormData();
    form.append('url', input.value);
    form.append('environment_id', (input.options?.environment_id as string | undefined) ?? HA_DEFAULT_ENV);
    for (const [k, v] of Object.entries(input.options ?? {})) {
        if (v != null && k !== 'environment_id') form.append(k, String(v));
    }

    try {
        const r = await fetch(`${HA_BASE}/submit/url`, {
            method: 'POST',
            headers: authHeaders(key),
            body: form,
        });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `Hybrid Analysis submit HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { job_id?: string; sha256?: string };
        const taskId = body?.job_id;
        if (!taskId) return { ok: false, error: `Hybrid Analysis submit returned no job_id: ${JSON.stringify(body).slice(0, 200)}` };
        const reportUrl = body.sha256
            ? `https://www.hybrid-analysis.com/sample/${body.sha256}/${taskId}`
            : `https://www.hybrid-analysis.com/`;
        return { ok: true, taskId, reportUrl };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

export async function haGetReport(taskId: string): Promise<HAReportResult> {
    const key = getApiKey();
    if (!key) return { ok: false, error: 'HYBRIDANALYSIS_API_KEY not configured' };

    try {
        // Try the cheaper state probe first; only fetch the summary when complete.
        const stateResp = await fetch(`${HA_BASE}/report/${encodeURIComponent(taskId)}/state`, {
            method: 'GET',
            headers: authHeaders(key),
        });
        if (!stateResp.ok) {
            const body = await stateResp.text().catch(() => '');
            return { ok: false, error: `Hybrid Analysis state HTTP ${stateResp.status}: ${body.slice(0, 200)}` };
        }
        const stateBody = await stateResp.json() as { state?: string };
        const stateMapped = mapHaState(stateBody.state);
        if (stateMapped !== 'completed') {
            return {
                ok: true,
                status: stateMapped,
                raw: stateBody,
                reportUrl: `https://www.hybrid-analysis.com/`,
            };
        }

        const summaryResp = await fetch(`${HA_BASE}/report/${encodeURIComponent(taskId)}/summary`, {
            method: 'GET',
            headers: authHeaders(key),
        });
        if (!summaryResp.ok) {
            const body = await summaryResp.text().catch(() => '');
            return { ok: false, error: `Hybrid Analysis summary HTTP ${summaryResp.status}: ${body.slice(0, 200)}` };
        }
        const summary = await summaryResp.json() as Record<string, unknown>;
        const mapped = mapHaSummary(summary);
        const sha = (summary as { sha256?: string }).sha256;
        return {
            ...mapped,
            ok: true,
            raw: summary,
            reportUrl: sha
                ? `https://www.hybrid-analysis.com/sample/${sha}/${taskId}`
                : `https://www.hybrid-analysis.com/`,
        };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

/** Normalise HA's lifecycle state strings. */
export function mapHaState(raw?: string): HAReportResult['status'] | undefined {
    switch (raw?.toUpperCase()) {
        case 'IN_QUEUE': case 'QUEUED': return 'queued';
        case 'IN_PROGRESS': case 'RUNNING': return 'running';
        case 'SUCCESS': case 'COMPLETED': return 'completed';
        case 'ERROR': case 'FAILED': return 'failed';
        case 'TIMEOUT': case 'TIMED_OUT': return 'timeout';
        default: return undefined;
    }
}

/**
 * Map HA's summary block into our normalised fields. HA reports
 * `verdict` ("malicious | suspicious | no specific threat | whitelisted")
 * and `threat_score` (0-100).
 */
export function mapHaSummary(summary: Record<string, unknown>): {
    status: 'completed';
    verdict?: HAReportResult['verdict'];
    score?: number;
} {
    const verdictRaw = (summary.verdict as string | undefined)?.toLowerCase();
    const verdict = ((): HAReportResult['verdict'] | undefined => {
        switch (verdictRaw) {
            case 'malicious': return 'malicious';
            case 'suspicious': return 'suspicious';
            case 'no specific threat': case 'whitelisted': case 'clean': case 'benign': return 'benign';
            default: return undefined;
        }
    })();
    const rawScore = summary.threat_score as number | undefined;
    const score = typeof rawScore === 'number' ? Math.max(0, Math.min(100, rawScore)) : undefined;
    if (verdict || score !== undefined) log.debug('HA summary mapped', { verdict, score });
    return { status: 'completed', verdict, score };
}
