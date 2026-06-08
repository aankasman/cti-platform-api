/**
 * Enrichment Provider Management — Configure enrichment sources
 *
 * Inspired by IntelOwl connector management.
 * Enable/disable providers, set priorities, configure API keys and rate limits.
 *
 * Mounts at: /v1/enrichment-providers/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import { UpdateEnrichmentProviderSchema } from '../../lib/schemas';

const log = createLogger('EnrichmentProviders');
const router = new Hono();
router.use('*', requireAuth);

// Built-in provider registry — matches existing enrichment services
const BUILT_IN_PROVIDERS: Record<string, { name: string; description: string; supportedTypes: string[]; requiresApiKey: boolean; docsUrl: string }> = {
    virustotal: { name: 'VirusTotal', description: 'Multi-AV scanning and threat intelligence', supportedTypes: ['ip', 'domain', 'url', 'hash'], requiresApiKey: true, docsUrl: 'https://docs.virustotal.com' },
    abuseipdb: { name: 'AbuseIPDB', description: 'IP address abuse reports and confidence scores', supportedTypes: ['ip'], requiresApiKey: true, docsUrl: 'https://docs.abuseipdb.com' },
    shodan: { name: 'Shodan', description: 'Internet-wide scanning and device intelligence (falls back to free InternetDB when no SHODAN_API_KEY is configured — slimmer payload but no setup required)', supportedTypes: ['ip', 'domain'], requiresApiKey: false, docsUrl: 'https://developer.shodan.io' },
    greynoise: { name: 'GreyNoise', description: 'Internet scanner classification — flags benign scanners (Shodan, Censys, researchers) so they can be deprioritised. Community endpoint works without GREYNOISE_API_KEY (50 lookups/day); with a free key the limit jumps to 10k/day.', supportedTypes: ['ip'], requiresApiKey: false, docsUrl: 'https://docs.greynoise.io' },
    urlscan: { name: 'urlscan.io', description: 'URL/domain scan history — fetches the most recent public scan with verdict, page metadata, and screenshot URL. Works unauthenticated (low quota) or with URLSCAN_API_KEY (1000 searches/day on the free tier).', supportedTypes: ['url', 'domain'], requiresApiKey: false, docsUrl: 'https://urlscan.io/docs/api/' },
    urlhaus: { name: 'URLhaus', description: 'Malicious URL database', supportedTypes: ['url', 'domain'], requiresApiKey: false, docsUrl: 'https://urlhaus.abuse.ch/api' },
    threatfox: { name: 'ThreatFox', description: 'IOC sharing platform by abuse.ch', supportedTypes: ['ip', 'domain', 'hash', 'url'], requiresApiKey: false, docsUrl: 'https://threatfox.abuse.ch/api' },
    geoip: { name: 'GeoIP', description: 'IP geolocation using MaxMind', supportedTypes: ['ip'], requiresApiKey: false, docsUrl: 'https://dev.maxmind.com' },
    whois: { name: 'WHOIS', description: 'Domain/IP registration lookup', supportedTypes: ['ip', 'domain'], requiresApiKey: false, docsUrl: 'https://www.iana.org/whois' },
    dnsresolver: { name: 'DNS Resolver', description: 'DNS record lookup', supportedTypes: ['domain'], requiresApiKey: false, docsUrl: '' },
    cve: { name: 'CVE/NVD', description: 'NIST NVD vulnerability database', supportedTypes: ['cve'], requiresApiKey: false, docsUrl: 'https://nvd.nist.gov/developers' },
};

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS enrichment_providers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                enabled BOOLEAN DEFAULT true,
                priority INT DEFAULT 50,
                supported_types TEXT[] DEFAULT '{}',
                requires_api_key BOOLEAN DEFAULT false,
                api_key_configured BOOLEAN DEFAULT false,
                rate_limit INT DEFAULT 0,
                timeout INT DEFAULT 10000,
                docs_url TEXT,
                last_used_at TIMESTAMPTZ,
                total_calls INT DEFAULT 0,
                total_errors INT DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
        `));
        // Seed built-in providers if not present
        for (const [id, p] of Object.entries(BUILT_IN_PROVIDERS)) {
            await rawQuery(sql.raw(`
                INSERT INTO enrichment_providers (id, name, description, supported_types, requires_api_key, docs_url)
                VALUES ('${id}', '${p.name.replace(/'/g, "''")}', '${p.description.replace(/'/g, "''")}',
                        ARRAY[${p.supportedTypes.map(t => `'${t}'`).join(',')}], ${p.requiresApiKey}, '${p.docsUrl}')
                ON CONFLICT (id) DO NOTHING
            `));
        }
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// GET /enrichment-providers — List all providers
router.get('/enrichment-providers', async (c) => {
    await ensureOnce();
    const result = await rawQuery(sql.raw(`SELECT * FROM enrichment_providers ORDER BY priority ASC, name ASC`));
    // Mask API keys — only show if configured
    const providers = (result.rows || []).map((r: Record<string, unknown>) => ({
        ...r,
        // Never expose actual API key
    }));
    return c.json({ success: true, data: providers });
});

// GET /enrichment-providers/:id
router.get('/enrichment-providers/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`SELECT * FROM enrichment_providers WHERE id = '${esc(id)}'`));
    if (!result.rows?.[0]) throw new NotFoundError('EnrichmentProvider', id);
    return c.json({ success: true, data: result.rows[0] });
});

// PUT /enrichment-providers/:id — Update provider config
router.put('/enrichment-providers/:id', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = UpdateEnrichmentProviderSchema.parse(await c.req.json().catch(() => ({})));
    const sets: string[] = ['updated_at = NOW()'];
    if (body.enabled !== undefined) sets.push(`enabled = ${body.enabled}`);
    if (body.priority !== undefined) sets.push(`priority = ${body.priority}`);
    if (body.apiKey !== undefined) {
        // Store a marker; actual key goes to env/vault in production
        sets.push(`api_key_configured = ${body.apiKey.length > 0}`);
        log.info('API key updated for provider', { provider: id, configured: body.apiKey.length > 0 });
    }
    if (body.rateLimit !== undefined) sets.push(`rate_limit = ${body.rateLimit}`);
    if (body.timeout !== undefined) sets.push(`timeout = ${body.timeout}`);
    const result = await rawQuery(sql.raw(`UPDATE enrichment_providers SET ${sets.join(', ')} WHERE id = '${esc(id)}' RETURNING *`));
    if (!result.rows?.[0]) throw new NotFoundError('EnrichmentProvider', id);
    return c.json({ success: true, data: result.rows[0] });
});

// POST /enrichment-providers/:id/test — Test provider connectivity
router.post('/enrichment-providers/:id/test', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const check = await rawQuery(sql.raw(`SELECT * FROM enrichment_providers WHERE id = '${esc(id)}'`));
    const provider = check.rows?.[0] as Record<string, unknown>;
    if (!provider) throw new NotFoundError('EnrichmentProvider', id);

    // Simulate connectivity test
    const start = Date.now();
    let reachable = true;
    let error: string | undefined;

    try {
        // Test basic connectivity for providers with known API endpoints
        const testUrls: Record<string, string> = {
            virustotal: 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
            abuseipdb: 'https://api.abuseipdb.com/api/v2/check',
            shodan: 'https://api.shodan.io/api-info',
            greynoise: 'https://api.greynoise.io/v3/community/8.8.8.8',
            urlhaus: 'https://urlhaus-api.abuse.ch/v1/',
            threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
        };
        const url = testUrls[id];
        if (url) {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            const resp = await fetch(url, { method: 'HEAD', signal: controller.signal }).catch(() => null);
            clearTimeout(timeout);
            reachable = resp !== null;
        }
    } catch (e) {
        reachable = false;
        error = (e as Error).message;
    }

    const latencyMs = Date.now() - start;
    return c.json({
        success: true,
        data: {
            provider: id,
            reachable,
            latencyMs,
            apiKeyConfigured: Boolean(provider.api_key_configured),
            enabled: Boolean(provider.enabled),
            error,
        },
    });
});

// GET /enrichment-providers/stats — Usage statistics
router.get('/enrichment-providers/stats', async (c) => {
    await ensureOnce();
    const result = await rawQuery(sql.raw(`
        SELECT id, name, enabled, priority, total_calls, total_errors,
               CASE WHEN total_calls > 0 THEN ROUND(total_errors * 100.0 / total_calls, 1) ELSE 0 END AS error_rate,
               last_used_at
        FROM enrichment_providers ORDER BY total_calls DESC
    `));
    return c.json({ success: true, data: result.rows || [] });
});

export default router;
