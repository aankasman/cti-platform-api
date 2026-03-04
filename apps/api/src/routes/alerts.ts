/**
 * Alerts Routes
 * 
 * API endpoints for managing and viewing alerts.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { alertStore } from '../queues/workers';
import { alertsQueue } from '../queues';
import { requireAuth } from '../middleware/auth';
import { NotFoundError, ValidationError } from '../lib/errors';
import { AlertListFilterSchema, CreateAlertSchema, UpdateAlertSchema, BulkAckSchema, EvaluateAlertSchema } from '../lib/schemas';
import { escInt } from '../lib/sanitize';

const alerts = new Hono();

// ============================================================================
// Alert Endpoints
// ============================================================================

/**
 * GET /v1/alerts
 * List alerts with pagination
 */
alerts.get('/', requireAuth, async (c) => {
    const { page, pageSize: limit, severity, unread: unreadOnly } = AlertListFilterSchema.parse(c.req.query());

    let filtered = [...alertStore];

    // Filter by severity
    if (severity) {
        filtered = filtered.filter(a => a.severity === severity);
    }

    // Filter by read status
    if (unreadOnly) {
        filtered = filtered.filter(a => !a.read);
    }

    const total = filtered.length;
    const start = (page - 1) * limit;
    const end = start + limit;
    const items = filtered.slice(start, end);

    return c.json({
        success: true,
        data: {
            alerts: items,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit),
            },
        },
    });
});

/**
 * GET /v1/alerts/unread/count
 * Get unread alert count for badge
 */
alerts.get('/unread/count', async (c) => {
    const unreadCount = alertStore.filter(a => !a.read).length;
    const highSeverityUnread = alertStore.filter(a => !a.read && (a.severity === 'high' || a.severity === 'critical')).length;

    return c.json({
        success: true,
        data: {
            unread: unreadCount,
            highSeverity: highSeverityUnread,
            timestamp: new Date().toISOString(),
        },
    });
});

/**
 * POST /v1/alerts/:id/read
 * Mark a single alert as read
 */
alerts.post('/:id/read', requireAuth, async (c) => {
    const id = c.req.param('id');
    const alert = alertStore.find(a => a.id === id);

    if (!alert) {
        throw new NotFoundError('Alert', id);
    }

    alert.read = true;

    return c.json({
        success: true,
        data: { alertId: id, read: true },
    });
});

/**
 * POST /v1/alerts/read-all
 * Mark all alerts as read
 */
alerts.post('/read-all', requireAuth, async (c) => {
    const count = alertStore.filter(a => !a.read).length;
    alertStore.forEach(a => a.read = true);

    return c.json({
        success: true,
        data: { markedRead: count },
    });
});

/**
 * POST /v1/alerts
 * Create a new alert (for testing or manual alerts)
 */
alerts.post('/', requireAuth, async (c) => {
    const body = await c.req.json();
    const { severity, type, title, message, source, metadata } = CreateAlertSchema.parse(body);

    const job = await alertsQueue.add(`manual-alert`, {
        severity,
        type,
        title,
        message,
        source: source || 'manual',
        metadata,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            severity,
            title,
            status: 'queued',
        },
    });
});

/**
 * PUT /v1/alerts/:id
 * Update an existing alert
 */
alerts.put('/:id', requireAuth, async (c) => {
    const id = c.req.param('id');
    const alert = alertStore.find(a => a.id === id);

    if (!alert) {
        throw new NotFoundError('Alert', id);
    }

    const body = await c.req.json();
    const updates = UpdateAlertSchema.parse(body);

    if (updates.severity) alert.severity = updates.severity;
    if (updates.title) alert.title = updates.title;
    if (updates.message) alert.message = updates.message;
    if (updates.metadata) alert.metadata = { ...alert.metadata, ...updates.metadata };
    if (typeof updates.read === 'boolean') alert.read = updates.read;
    alert.updatedAt = new Date().toISOString();

    return c.json({
        success: true,
        data: alert,
    });
});

/**
 * DELETE /v1/alerts/:id
 * Delete an alert
 */
alerts.delete('/:id', requireAuth, async (c) => {
    const id = c.req.param('id');
    const index = alertStore.findIndex(a => a.id === id);

    if (index === -1) {
        throw new NotFoundError('Alert', id);
    }

    alertStore.splice(index, 1);

    return c.json({
        success: true,
        message: 'Alert deleted',
        data: { id },
    });
});

/**
 * POST /v1/alerts/:id/acknowledge
 * Acknowledge an alert
 */
alerts.post('/:id/acknowledge', requireAuth, async (c) => {
    const id = c.req.param('id');
    const alert = alertStore.find(a => a.id === id);

    if (!alert) {
        throw new NotFoundError('Alert', id);
    }

    alert.read = true;
    alert.acknowledged = true;
    alert.acknowledgedAt = new Date().toISOString();

    return c.json({
        success: true,
        data: { alertId: id, acknowledged: true },
    });
});

/**
 * POST /v1/alerts/evaluate
 * Evaluate IOCs against composite risk-score threshold and create alerts.
 * Body: { threshold?: number (default 75) }
 */
alerts.post('/evaluate', requireAuth, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const { threshold } = EvaluateAlertSchema.parse(body);

    const { rawQuery } = await import('@rinjani/db');
    const result = await rawQuery(
        `SELECT id, type, value, risk_score, source, threat_type
         FROM iocs
         WHERE risk_score >= ${escInt(threshold)}
         AND id NOT IN (
             SELECT (metadata->>'iocId')::uuid FROM unnest(ARRAY[]::jsonb[])
         )
         ORDER BY risk_score DESC
         LIMIT 50`
    );

    const rows = result.rows || [];
    let created = 0;

    for (const ioc of rows as Array<{ id: string; value: string; type: string; risk_score: number; source?: string; threat_type?: string }>) {
        // Check if alert already exists for this IOC
        const exists = alertStore.some(
            a => a.metadata?.iocId === ioc.id && a.type === 'high_risk_ioc'
        );
        if (exists) continue;

        const severity = ioc.risk_score >= 90 ? 'critical' : ioc.risk_score >= 80 ? 'high' : 'medium';
        const alert = {
            id: crypto.randomUUID(),
            type: 'high_risk_ioc',
            severity,
            title: `High-Risk IOC Detected: ${ioc.value}`,
            message: `IOC ${ioc.value} (${ioc.type}) has a composite risk score of ${ioc.risk_score}. Source: ${ioc.source || 'unknown'}. Threat type: ${ioc.threat_type || 'unknown'}.`,
            source: 'scoring-engine',
            read: false,
            acknowledged: false,
            metadata: {
                iocId: ioc.id,
                iocValue: ioc.value,
                iocType: ioc.type,
                riskScore: ioc.risk_score,
                threshold,
            },
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };

        alertStore.unshift(alert as typeof alertStore[number]);
        created++;
    }

    // Trim alertStore to max 500
    if (alertStore.length > 500) alertStore.length = 500;

    return c.json({
        success: true,
        data: {
            evaluated: rows.length,
            alertsCreated: created,
            threshold,
        },
    });
});


// ============================================================================
// Alert Lifecycle Enhancements (Phase AG — TheHive inspired)
// ============================================================================

import { AlertEscalateSchema } from '../lib/schemas';
import { requireRole } from '../middleware/auth';

/**
 * POST /v1/alerts/:id/escalate
 * Escalate alert to a higher priority (TheHive alert→case inspired)
 */
alerts.post('/:id/escalate', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id');
    const body = AlertEscalateSchema.parse(await c.req.json().catch(() => ({})));
    const alert = alertStore.find(a => a.id === id);

    if (!alert) {
        throw new NotFoundError('Alert', id);
    }

    alert.severity = body.priority;
    alert.read = false; // Re-flag as unread after escalation
    alert.metadata = {
        ...alert.metadata,
        escalated: true,
        escalatedAt: new Date().toISOString(),
        escalatedBy: c.get('user')?.id || 'unknown',
        assignee: body.assignee || undefined,
        escalationNotes: body.notes || undefined,
        escalationTags: body.tags,
    };
    alert.updatedAt = new Date().toISOString();

    return c.json({
        success: true,
        data: {
            alertId: id,
            escalated: true,
            priority: body.priority,
            assignee: body.assignee,
        },
    });
});

/**
 * POST /v1/alerts/bulk-acknowledge
 * Acknowledge multiple alerts at once
 */
alerts.post('/bulk-acknowledge', requireAuth, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const { ids } = z.object({
        ids: z.array(z.string().min(1)).min(1).max(500),
    }).parse(body);

    let acknowledged = 0;
    for (const id of ids) {
        const alert = alertStore.find(a => a.id === id);
        if (alert && !alert.acknowledged) {
            alert.read = true;
            alert.acknowledged = true;
            alert.acknowledgedAt = new Date().toISOString();
            acknowledged++;
        }
    }

    return c.json({
        success: true,
        data: {
            requested: ids.length,
            acknowledged,
        },
    });
});

export default alerts;
