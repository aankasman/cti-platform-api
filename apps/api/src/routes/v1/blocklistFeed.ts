/**
 * Phase 4 #4 — Vendor-specific blocklist feed endpoint.
 *
 *   GET /v1/feeds/blocklist/:vendor/:type
 *     vendor: fortinet | paloalto | cisco
 *     type:   ip | domain | url
 *
 * Returns a vendor-formatted EDL ready for a firewall to subscribe to.
 *
 * Caching:
 *   - Stable URL → 5-minute Cache-Control + ETag = SHA-256 of body
 *   - The HMAC signature header (`X-Rinjani-Signature`) lets the
 *     downstream box verify the body wasn't tampered with in transit
 *
 * Auth: this is intentionally public-readable so firewalls can subscribe
 * without baking credentials. Signing is the integrity layer. If an
 * operator needs auth, they can put the API behind a reverse proxy or
 * gate via `BLOCKLIST_FEED_REQUIRE_AUTH=true`.
 *
 * Secret:
 *   BLOCKLIST_FEED_SECRET env var. If unset, a per-process random
 *   secret is generated at startup — feeds become rotation-on-restart,
 *   which is correct dev behaviour. Production should set this.
 */
import { Hono } from 'hono';
import { createHash, randomBytes } from 'node:crypto';
import { rawQuery, sql } from '@rinjani/db';
import { createLogger } from '../../lib/logger';
import { BlocklistFeedSchema } from '../../lib/schemas';
import {
    toFortinetFeed, toPaloAltoEdl, toCiscoFeed, hmacSign,
    type BlocklistIOC, type BlocklistEntryType,
} from '@rinjani/core/blocklistFormatters';
import { requireAuth } from '../../middleware/auth';

const log = createLogger('BlocklistFeed');
const feedRouter = new Hono();

// Per-process random fallback so the signature is *some* value when the
// operator hasn't set BLOCKLIST_FEED_SECRET. Rotated on restart.
let SECRET_CACHE: string | null = null;
function feedSecret(): string {
    const envSecret = process.env.BLOCKLIST_FEED_SECRET;
    if (envSecret) return envSecret;
    if (!SECRET_CACHE) {
        SECRET_CACHE = randomBytes(32).toString('hex');
        log.warn('BLOCKLIST_FEED_SECRET not set; using a per-process fallback (rotates on restart)');
    }
    return SECRET_CACHE;
}

async function fetchBlocklistIocs(kind: BlocklistEntryType, severity: string | null, limit: number): Promise<BlocklistIOC[]> {
    const typeFilter = kind === 'ip'
        ? `type IN ('ip', 'ipv4', 'ipv6')`
        : kind === 'domain'
            ? `type IN ('domain', 'hostname')`
            : `type = 'url'`;
    const sevFilter = severity ? `AND severity = '${severity.replace(/'/g, "''")}'` : '';
    const rows = await rawQuery<{ type: string; value: string; severity: string | null; source: string | null }>(sql.raw(`
        SELECT type, value, severity, source
        FROM iocs
        WHERE ${typeFilter} ${sevFilter}
          AND (revoked IS NULL OR revoked = false)
        ORDER BY COALESCE(last_seen, created_at) DESC
        LIMIT ${limit}
    `));
    return rows.rows ?? [];
}

const VENDOR_FORMATTERS: Record<string, (iocs: BlocklistIOC[], kind: BlocklistEntryType) => string> = {
    fortinet: toFortinetFeed,
    paloalto: toPaloAltoEdl,
    cisco: toCiscoFeed,
};

const requireAuthMaybe = process.env.BLOCKLIST_FEED_REQUIRE_AUTH === 'true' ? requireAuth : undefined;
if (requireAuthMaybe) feedRouter.use('*', requireAuthMaybe);

feedRouter.get('/feeds/blocklist/:vendor/:type', async (c) => {
    const { vendor, type } = c.req.param();
    const filters = BlocklistFeedSchema.parse({ ...c.req.query() });

    const formatter = VENDOR_FORMATTERS[vendor.toLowerCase()];
    if (!formatter) {
        return c.json({ success: false, error: { message: `Unknown vendor: ${vendor}. Use one of: ${Object.keys(VENDOR_FORMATTERS).join(', ')}` } }, 400);
    }
    if (type !== 'ip' && type !== 'domain' && type !== 'url') {
        return c.json({ success: false, error: { message: `type must be one of: ip, domain, url` } }, 400);
    }

    const iocs = await fetchBlocklistIocs(type, filters.severity ?? null, filters.limit);
    const body = formatter(iocs, type);
    const signature = await hmacSign(body, feedSecret());
    const etag = `"${createHash('sha256').update(body).digest('hex').slice(0, 16)}"`;

    log.info('blocklist feed served', { vendor, type, severity: filters.severity, count: iocs.length });

    // If the client sent If-None-Match and it matches, return 304
    if (c.req.header('If-None-Match') === etag) {
        return new Response(null, { status: 304, headers: { 'ETag': etag } });
    }

    return new Response(body, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `inline; filename="rinjani-${vendor}-${type}.txt"`,
            'Cache-Control': 'public, max-age=300',
            'ETag': etag,
            'X-Rinjani-Signature': `sha256=${signature}`,
            'X-Rinjani-Record-Count': String(iocs.length),
        },
    });
});

export default feedRouter;
