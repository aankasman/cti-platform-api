/**
 * IOC Routes (Indicators of Compromise)
 *
 * Extracted from v1.ts — list and detail endpoints for IOCs.
 * Supports both offset pagination (/iocs) and cursor pagination (/iocs/cursor).
 */

import { Hono } from 'hono';
import * as opensearch from '../../services/opensearch';
import { NotFoundError } from '../../lib/errors';
import { IOCFilterSchema } from '../../lib/schemas';
import { paginate } from './helpers';
import { parseCursorParams, buildCursorResponse } from '../../lib/pagination';
import { rawQuery, sql } from '@rinjani/db';

const router = new Hono();

// ============================================================================
// IOCs (Indicators of Compromise) — Offset Pagination (OpenSearch)
// ============================================================================

router.get('/iocs', async (c) => {
    const { page, pageSize, q, type, source, severity, dateFrom, dateTo } = IOCFilterSchema.parse(c.req.query());

    // Use OpenSearch for fast search with facets
    const result = await opensearch.unifiedSearch({
        query: q || '',
        filters: {
            entityType: ['ioc'],
            ...(type ? { source: [type] } : {}), // type maps to OpenSearch type field
            ...(source ? { source: [source] } : {}),
            ...(severity ? { severity: [severity] } : {}),
            ...(dateFrom ? { dateFrom } : {}),
            ...(dateTo ? { dateTo } : {}),
        },
        sort: { field: 'updatedAt', order: 'desc' },
        pagination: { page, limit: pageSize },
        aggregations: true,
    });

    // Map OpenSearch fields to frontend-expected names for IOCs
    const mappedItems = result.items.map((item: Record<string, unknown>) => ({
        ...item,
        threatType: item.description !== 'unknown' ? item.description : null,
        firstSeen: item.createdAt,
        lastSeen: item.updatedAt,
    }));

    return c.json({
        success: true,
        data: {
            items: mappedItems,
            filters: { type, source, severity, q },
            pagination: paginate(page, pageSize, result.total),
            facets: result.facets,
            took: result.took,
        },
    });
});

// ============================================================================
// IOCs — Cursor Pagination (PostgreSQL direct, O(1) seek)
// ============================================================================

router.get('/iocs/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    // Build WHERE clause for cursor seek
    let whereClause = '';
    if (cursor) {
        const op = direction === 'next' ? '<' : '>';
        whereClause = `WHERE (updated_at, id::text) ${op} ('${cursor.timestamp}', '${cursor.id.replace(/'/g, "''")}')`;
    }

    const orderDir = direction === 'next' ? 'DESC' : 'ASC';

    const result = await rawQuery(
        `SELECT id, type, value, source, threat_type, confidence, severity,
                risk_score, first_seen, last_seen, tags, created_at, updated_at
         FROM iocs ${whereClause}
         ORDER BY updated_at ${orderDir}, id ${orderDir}
         LIMIT ${limit + 1}`
    );

    const rows = (result.rows || []).map((row: Record<string, unknown>) => ({
        ...row,
        threatType: row.threat_type,
        firstSeen: row.first_seen,
        lastSeen: row.last_seen,
        riskScore: row.risk_score,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    }));

    // Reverse order for 'prev' direction queries
    if (direction === 'prev') rows.reverse();

    const response = buildCursorResponse(rows, limit, (row: Record<string, unknown>) => ({
        timestamp: String(row.updated_at || row.created_at || ''),
        id: String(row.id || ''),
    }));

    return c.json({ success: true, ...response });
});

// ============================================================================
// Get IOC by ID (UUID) or value
// ============================================================================

router.get('/iocs/:idOrValue', async (c) => {
    const { idOrValue } = c.req.param();

    // Try OpenSearch first (fast, indexed)
    const result = await opensearch.getById(idOrValue, 'ioc');

    if (result.item) {
        const item = result.item;
        const mappedData = {
            ...item,
            threatType: item.description !== 'unknown' ? item.description : null,
            firstSeen: item.createdAt,
            lastSeen: item.updatedAt,
        };
        return c.json({ success: true, data: mappedData, took: result.took });
    }

    // Fallback: query PostgreSQL directly (handles IOCs not yet indexed in OpenSearch)
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(idOrValue);
    const pgResult = await rawQuery(
        isUUID
            ? sql`SELECT * FROM iocs WHERE id = ${idOrValue} LIMIT 1`
            : sql`SELECT * FROM iocs WHERE value = ${idOrValue} LIMIT 1`
    );

    const row = pgResult.rows?.[0];
    if (!row) {
        throw new NotFoundError('IOC', idOrValue);
    }

    const mappedData = {
        id: row.id,
        type: row.type,
        value: row.value,
        source: row.source,
        severity: row.severity,
        confidence: row.confidence,
        tags: row.tags,
        description: row.description ?? row.threat_type,
        threatType: row.threat_type,
        riskScore: row.risk_score,
        firstSeen: row.first_seen,
        lastSeen: row.last_seen,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        entityType: 'ioc',
    };

    return c.json({ success: true, data: mappedData, source: 'database' });
});

// ============================================================================
// IOC Lifecycle Management (MISP / STIX 2.1 inspired)
// ============================================================================

import { requireAuth, requireRole } from '../../middleware/auth';
import {
    IOCUpdateSchema, IOCRevokeSchema, IOCExpireSchema, IOCVerdictSchema,
} from '../../lib/schemas';

/** PUT /v1/iocs/:id — Partial update of IOC fields */
router.put('/iocs/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = IOCUpdateSchema.parse(await c.req.json().catch(() => ({})));

    const setClauses: string[] = ['updated_at = NOW()'];
    const esc = (s: string) => s.replace(/'/g, "''");

    if (body.severity) setClauses.push(`severity = '${esc(body.severity)}'`);
    if (body.confidence !== undefined) setClauses.push(`confidence = ${body.confidence}`);
    if (body.tags) setClauses.push(`tags = ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]`);
    if (body.threatType) setClauses.push(`threat_type = '${esc(body.threatType)}'`);
    if (body.notes) setClauses.push(`raw_data = COALESCE(raw_data, '{}'::jsonb) || '${JSON.stringify({ notes: body.notes }).replace(/'/g, "''")}'::jsonb`);

    const result = await rawQuery(sql.raw(`
        UPDATE iocs SET ${setClauses.join(', ')} WHERE id = '${esc(id)}'
        RETURNING id, type, value, severity, confidence, tags, threat_type, updated_at
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: row });
});

/** POST /v1/iocs/:id/revoke — Mark IOC as revoked (soft-delete with reason) */
router.post('/iocs/:id/revoke', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = IOCRevokeSchema.parse(await c.req.json().catch(() => ({})));
    const esc = (s: string) => s.replace(/'/g, "''");

    const revokeData = JSON.stringify({ revoked: true, revokeReason: body.reason, revokedAt: new Date().toISOString() }).replace(/'/g, "''");
    const result = await rawQuery(sql.raw(`
        UPDATE iocs SET
            raw_data = COALESCE(raw_data, '{}'::jsonb) || '${revokeData}'::jsonb,
            updated_at = NOW()
        WHERE id = '${esc(id)}'
        RETURNING id, type, value
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: { ...row, revoked: true, reason: body.reason } });
});

/** POST /v1/iocs/:id/expire — Set valid_until date for automatic expiry */
router.post('/iocs/:id/expire', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = IOCExpireSchema.parse(await c.req.json().catch(() => ({})));
    const esc = (s: string) => s.replace(/'/g, "''");

    const expireData = JSON.stringify({ validUntil: body.validUntil }).replace(/'/g, "''");
    const result = await rawQuery(sql.raw(`
        UPDATE iocs SET
            raw_data = COALESCE(raw_data, '{}'::jsonb) || '${expireData}'::jsonb,
            updated_at = NOW()
        WHERE id = '${esc(id)}'
        RETURNING id, type, value
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: { ...row, validUntil: body.validUntil } });
});

/** POST /v1/iocs/:id/verdict — Assign analyst verdict */
router.post('/iocs/:id/verdict', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = IOCVerdictSchema.parse(await c.req.json().catch(() => ({})));
    const esc = (s: string) => s.replace(/'/g, "''");
    const userId = c.get('user')?.id || 'unknown';

    const verdictData = JSON.stringify({
        verdict: body.verdict,
        verdictNotes: body.notes,
        verdictBy: userId,
        verdictAt: new Date().toISOString(),
    }).replace(/'/g, "''");

    const result = await rawQuery(sql.raw(`
        UPDATE iocs SET
            raw_data = COALESCE(raw_data, '{}'::jsonb) || '${verdictData}'::jsonb,
            updated_at = NOW()
        WHERE id = '${esc(id)}'
        RETURNING id, type, value
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: { ...row, verdict: body.verdict } });
});

export default router;


