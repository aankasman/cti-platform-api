/**
 * Audit API Routes
 * 
 * Endpoints for querying audit logs and entity history.
 */

import { Hono } from 'hono';
import { queryAuditLogs, getEntityHistory, getAuditStats } from '@rinjani/core/audit';
import type { EntityType, AuditAction } from '@rinjani/core/audit';
import { requireAuth, requireRole } from '../../../middleware/auth';
import { ValidationError } from '../../../lib/errors';
import { AuditFilterSchema } from '../../../lib/schemas';

export const auditRouter = new Hono();

// Require authentication for all audit routes
auditRouter.use('*', requireAuth);

// ============================================================================
// Audit Log Queries
// ============================================================================

/**
 * GET /v1/audit
 * Query audit logs with filters
 */
auditRouter.get('/', requireRole('admin', 'analyst'), (c) => {
    const { entityType, entityId, action, source, limit, offset } = AuditFilterSchema.parse(c.req.query());

    const result = queryAuditLogs({
        entityType: entityType as EntityType | undefined,
        entityId,
        action: action as AuditAction | undefined,
        source,
        limit: Math.min(limit, 100),
        offset,
    });

    return c.json({
        success: true,
        data: {
            entries: result.entries,
            pagination: {
                total: result.total,
                limit,
                offset,
                hasMore: offset + limit < result.total,
            },
        },
    });
});

/**
 * GET /v1/audit/stats
 * Get audit statistics
 */
auditRouter.get('/stats', requireRole('admin'), (c) => {
    const stats = getAuditStats();

    return c.json({
        success: true,
        data: stats,
    });
});

/**
 * GET /v1/audit/entity/:type/:id
 * Get full history for a specific entity
 */
auditRouter.get('/entity/:type/:id', requireRole('admin', 'analyst'), (c) => {
    const { type, id } = c.req.param();

    const validTypes = ['ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware'];
    if (!validTypes.includes(type)) {
        throw new ValidationError(`Invalid entity type. Must be one of: ${validTypes.join(', ')}`);
    }

    const history = getEntityHistory(type as EntityType, id);

    return c.json({
        success: true,
        data: {
            entityType: type,
            entityId: id,
            history,
            changeCount: history.length,
        },
    });
});

export default auditRouter;
