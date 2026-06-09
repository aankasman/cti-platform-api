/**
 * Splunk HTTP Event Collector (HEC) client — Phase 4 #2 closer.
 *
 * The CEF/LEEF/ECS codecs in `@rinjani/core/siemFormatters` already
 * produce vendor-neutral output for download. This is the thin push
 * client that ships the same data **directly** to a Splunk endpoint
 * over HEC instead of forcing the operator to scrape and forward.
 *
 * API: https://docs.splunk.com/Documentation/Splunk/latest/Data/HECRESTendpoints
 *   POST <base>/services/collector/event
 *   Headers: Authorization: Splunk <token>
 *   Body:   one event per line, each `{ event: <payload>, sourcetype?, index?, host?, time? }`
 *
 * Auth model: HEC token (Splunk Web → Settings → Data inputs → HTTP Event Collector).
 *
 * Behaviour without credentials:
 *   - `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN` missing → returns
 *     `{ ok: false, error: 'not configured' }`. Route returns 502.
 */
import { createLogger } from '../../lib/logger';
import { toEcs, type SiemIOC, type EcsDoc } from '@rinjani/core/siemFormatters';

const log = createLogger('SplunkHEC');

interface SplunkConfig {
    baseUrl: string;
    token: string;
    index?: string;
    sourcetype: string;
    insecureTls: boolean;
}

function getConfig(): SplunkConfig | null {
    const baseUrl = process.env.SPLUNK_HEC_URL?.trim();
    const token = process.env.SPLUNK_HEC_TOKEN?.trim();
    if (!baseUrl || !token) return null;
    return {
        baseUrl: baseUrl.replace(/\/+$/, ''),
        token,
        index: process.env.SPLUNK_HEC_INDEX?.trim() || undefined,
        sourcetype: process.env.SPLUNK_HEC_SOURCETYPE?.trim() || 'rinjani:cti:ioc',
        insecureTls: process.env.SPLUNK_HEC_INSECURE_TLS === 'true',
    };
}

export interface SplunkPushResult {
    ok: boolean;
    batchSize: number;
    /** Number of events Splunk accepted. HEC returns one ack per request, not per event. */
    accepted: number;
    error?: string;
    /** HTTP status returned by HEC on failure. */
    status?: number;
}

/** Build the HEC body — one `{event, ...}` object per line. */
export function toHecBody(iocs: SiemIOC[], cfg: { index?: string; sourcetype: string }): string {
    return iocs.map(ioc => {
        const event: EcsDoc = toEcs(ioc);
        const envelope: Record<string, unknown> = {
            event,
            sourcetype: cfg.sourcetype,
        };
        if (cfg.index) envelope.index = cfg.index;
        // Splunk wants `time` in epoch seconds (or ms with decimal) — use the IOC timestamp if present.
        const tsSource = ioc.lastSeen ?? ioc.firstSeen;
        if (tsSource) {
            const ms = new Date(tsSource).getTime();
            if (Number.isFinite(ms)) envelope.time = ms / 1000;
        }
        return JSON.stringify(envelope);
    }).join('\n');
}

export async function pushToSplunk(iocs: SiemIOC[], override?: { index?: string; sourcetype?: string }): Promise<SplunkPushResult> {
    const cfg = getConfig();
    if (!cfg) return { ok: false, batchSize: 0, accepted: 0, error: 'Splunk HEC not configured (need SPLUNK_HEC_URL + SPLUNK_HEC_TOKEN)' };
    if (iocs.length === 0) return { ok: true, batchSize: 0, accepted: 0 };

    const body = toHecBody(iocs, {
        index: override?.index ?? cfg.index,
        sourcetype: override?.sourcetype ?? cfg.sourcetype,
    });

    try {
        const r = await fetch(`${cfg.baseUrl}/services/collector/event`, {
            method: 'POST',
            headers: {
                'Authorization': `Splunk ${cfg.token}`,
                'Content-Type': 'application/json',
                'User-Agent': 'RinjaniCTI/1.0',
            },
            body,
        });
        if (!r.ok) {
            const text = await r.text().catch(() => '');
            log.warn('Splunk HEC rejected', { status: r.status, body: text.slice(0, 200) });
            return { ok: false, batchSize: iocs.length, accepted: 0, status: r.status, error: `HEC ${r.status}: ${text.slice(0, 200)}` };
        }
        log.info('Splunk HEC accepted batch', { count: iocs.length });
        return { ok: true, batchSize: iocs.length, accepted: iocs.length };
    } catch (err) {
        return { ok: false, batchSize: iocs.length, accepted: 0, error: (err as Error).message };
    }
}
