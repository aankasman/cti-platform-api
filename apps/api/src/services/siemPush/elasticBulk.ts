/**
 * Elastic _bulk push client — Phase 4 #2 closer.
 *
 * Direct push of ECS-shaped IOCs to an Elasticsearch / OpenSearch cluster
 * via the standard `_bulk` endpoint. Same idea as the Splunk HEC client
 * (this file's sibling) — vendor-neutral codecs already exist; this is
 * the thin HTTP wrapper that ships them.
 *
 * API: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
 *   POST <base>/_bulk
 *   Content-Type: application/x-ndjson
 *   Body: pairs of (action-meta, doc) lines, NDJSON
 *
 * Auth: API key (preferred — `Authorization: ApiKey <base64>`) or Basic
 * (`Authorization: Basic <base64(user:pass)>`). API key takes priority
 * if both are set.
 *
 * Behaviour without credentials:
 *   - `ELASTIC_URL` missing → `{ ok: false, error: 'not configured' }`.
 *   - `ELASTIC_URL` set but no `ELASTIC_API_KEY` and no
 *     `ELASTIC_USER`+`ELASTIC_PASSWORD` → returns the same error
 *     (we don't push to a cluster without credentials, even one that
 *     might allow anonymous writes).
 */
import { createLogger } from '../../lib/logger';
import { toEcs, type SiemIOC, type EcsDoc } from '@rinjani/core/siemFormatters';

const log = createLogger('ElasticBulk');

interface ElasticConfig {
    baseUrl: string;
    index: string;
    authHeader: string;
}

function getConfig(): ElasticConfig | { error: string } {
    const baseUrl = process.env.ELASTIC_URL?.trim();
    if (!baseUrl) return { error: 'Elastic not configured (need ELASTIC_URL)' };

    const index = process.env.ELASTIC_INDEX?.trim() || 'rinjani-cti-iocs';
    const apiKey = process.env.ELASTIC_API_KEY?.trim();
    const user = process.env.ELASTIC_USER?.trim();
    const pass = process.env.ELASTIC_PASSWORD?.trim();

    let authHeader: string;
    if (apiKey) {
        authHeader = `ApiKey ${apiKey}`;
    } else if (user && pass) {
        authHeader = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    } else {
        return { error: 'Elastic credentials required (set ELASTIC_API_KEY or ELASTIC_USER + ELASTIC_PASSWORD)' };
    }

    return { baseUrl: baseUrl.replace(/\/+$/, ''), index, authHeader };
}

export interface ElasticPushResult {
    ok: boolean;
    batchSize: number;
    /** Number of items the cluster successfully indexed. */
    indexed: number;
    /** Per-item errors collected from the response (capped). */
    errors: Array<{ id: string; status: number; type: string; reason: string }>;
    error?: string;
    status?: number;
}

/**
 * Build the NDJSON body for `_bulk`. Each IOC produces two lines:
 *   { "index": { "_index": "...", "_id": "..." } }
 *   { ...ECS doc... }
 *
 * Using the IOC id as the document `_id` makes pushes idempotent — re-running
 * the same export upserts instead of duplicating.
 */
export function toBulkBody(iocs: SiemIOC[], index: string): string {
    return iocs.flatMap(ioc => {
        const meta = JSON.stringify({ index: { _index: index, _id: ioc.id } });
        const doc: EcsDoc = toEcs(ioc);
        return [meta, JSON.stringify(doc)];
    }).join('\n') + (iocs.length > 0 ? '\n' : '');
}

interface BulkResponseItem {
    index?: { _id?: string; status?: number; error?: { type?: string; reason?: string } };
}
interface BulkResponse {
    took?: number;
    errors?: boolean;
    items?: BulkResponseItem[];
}

export async function pushToElastic(iocs: SiemIOC[], override?: { index?: string }): Promise<ElasticPushResult> {
    const cfgOrErr = getConfig();
    if ('error' in cfgOrErr) {
        return { ok: false, batchSize: 0, indexed: 0, errors: [], error: cfgOrErr.error };
    }
    if (iocs.length === 0) return { ok: true, batchSize: 0, indexed: 0, errors: [] };

    const cfg = cfgOrErr;
    const index = override?.index ?? cfg.index;
    const body = toBulkBody(iocs, index);

    try {
        const r = await fetch(`${cfg.baseUrl}/_bulk`, {
            method: 'POST',
            headers: {
                'Authorization': cfg.authHeader,
                'Content-Type': 'application/x-ndjson',
                'User-Agent': 'RinjaniCTI/1.0',
            },
            body,
        });
        if (!r.ok) {
            const text = await r.text().catch(() => '');
            log.warn('Elastic _bulk rejected', { status: r.status, body: text.slice(0, 200) });
            return { ok: false, batchSize: iocs.length, indexed: 0, errors: [], status: r.status, error: `_bulk ${r.status}: ${text.slice(0, 200)}` };
        }

        const json = await r.json() as BulkResponse;
        const items = json.items ?? [];
        const errors: ElasticPushResult['errors'] = [];
        let indexed = 0;
        for (const it of items) {
            const op = it.index;
            if (!op) continue;
            if (op.error) {
                if (errors.length < 25) {
                    errors.push({
                        id: op._id ?? '',
                        status: op.status ?? 0,
                        type: op.error.type ?? 'unknown',
                        reason: (op.error.reason ?? '').slice(0, 200),
                    });
                }
            } else if ((op.status ?? 0) >= 200 && (op.status ?? 0) < 300) {
                indexed++;
            }
        }

        const ok = !json.errors;
        log.info('Elastic _bulk processed', { count: iocs.length, indexed, errorCount: items.length - indexed });
        return { ok, batchSize: iocs.length, indexed, errors };
    } catch (err) {
        return { ok: false, batchSize: iocs.length, indexed: 0, errors: [], error: (err as Error).message };
    }
}
