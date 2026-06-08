/**
 * Notifications API Routes
 * 
 * Manages notification preferences and manual alert triggers.
 */

import { Hono } from 'hono';
import { db, sql } from '@rinjani/db';
import { createLogger } from '../lib/logger';
import {
    NotificationSettingsSchema, TestSlackSchema, TestEmailSchema, ManualAlertSchema,
    TestChannelWebhookSchema, EvaluateRulesSchema,
} from '../lib/schemas';
import {
    sendTeamsNotification, sendDiscordNotification, sendPagerDutyNotification,
    resolveRuleChannels, dispatchToChannels, type ChannelKind,
} from '../services/notificationChannels';

const log = createLogger('notifications');
import {
    sendSlackNotification,
    sendEmailNotification,
    broadcastNotification,
    createAlertPayload,
    createInAppNotification,
    getInAppNotifications,
    getUnreadCount,
    markNotificationsRead,
} from '../services/notifications';

import { requireAuth } from '../middleware/auth';

const notifications = new Hono();

// ============================================================================
// Public / read-only endpoints (no auth required — global optionalAuth applies)
// ============================================================================

/**
 * GET /notifications/unread-count
 * Badge count for the dashboard bell icon
 */
notifications.get('/unread-count', async (c) => {
    const count = await getUnreadCount();
    return c.json({ success: true, data: { count } });
});

/**
 * GET /notifications
 * List recent in-app notifications (dashboard bell dropdown)
 */
notifications.get('/', async (c) => {
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const offset = parseInt(c.req.query('offset') || '0', 10);
    const items = await getInAppNotifications(limit, offset);
    return c.json({ success: true, data: items });
});

/**
 * POST /notifications
 * Create an in-app notification (bell dropdown)
 */
notifications.post('/', async (c) => {
    const { type = 'info', title, message, source = 'system', metadata } = await c.req.json();
    if (!title || !message) return c.json({ success: false, error: 'title and message required' }, 400);
    const notif = await createInAppNotification({ type, title, message, source, metadata });
    return c.json({ success: true, data: notif });
});

// ============================================================================
// Protected endpoints — require authentication
// ============================================================================

/**
 * POST /notifications/mark-read
 * Mark a single notification (body.id) or all as read
 */
notifications.post('/mark-read', requireAuth, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    await markNotificationsRead(body.id);
    return c.json({ success: true });
});


// ============================================================================
// Notification Settings CRUD
// ============================================================================

/**
 * GET /notifications/settings
 * Get notification settings for current user
 */
notifications.get('/settings', requireAuth, async (c) => {
    try {
        // In real implementation, get userId from auth context
        const userId = c.req.header('X-User-Id') || 'default';

        // For now, return default settings (table may not exist yet)
        // In production, query the notification_configs table
        return c.json({
            success: true,
            data: {
                emailEnabled: false,
                emailAddress: null,
                slackEnabled: false,
                slackWebhookUrl: null,
                severityThreshold: 'high',
                notifyOnNewIOC: true,
                notifyOnNewVuln: true,
                notifyOnThreatActor: true,
            },
        });
    } catch (error) {
        // Return defaults on any error
        return c.json({
            success: true,
            data: {
                emailEnabled: false,
                emailAddress: null,
                slackEnabled: false,
                slackWebhookUrl: null,
                severityThreshold: 'high',
                notifyOnNewIOC: true,
                notifyOnNewVuln: true,
                notifyOnThreatActor: true,
            },
        });
    }
});

/**
 * PUT /notifications/settings
 * Update notification settings
 */
notifications.put('/settings', requireAuth, async (c) => {
    const body = NotificationSettingsSchema.parse(await c.req.json());

    // For now, just acknowledge the settings (no database table yet)
    // In production, persist to notification_configs table
    log.info('Notification settings updated', { settings: body });

    return c.json({ success: true, message: 'Settings updated' });
});

// ============================================================================
// Test Notifications
// ============================================================================

/**
 * POST /notifications/test/slack
 * Test Slack webhook integration
 */
notifications.post('/test/slack', requireAuth, async (c) => {
    const { webhookUrl } = TestSlackSchema.parse(await c.req.json());

    const result = await sendSlackNotification(webhookUrl, {
        type: 'alert',
        severity: 'medium',
        title: 'Test Notification',
        message: 'This is a test notification from Rinjani CTI Platform.',
    });

    return c.json({ success: result.success, error: result.error });
});

/**
 * POST /notifications/test/email
 * Test email integration
 */
notifications.post('/test/email', requireAuth, async (c) => {
    const { emailAddress } = TestEmailSchema.parse(await c.req.json());

    const result = await sendEmailNotification(emailAddress, {
        type: 'alert',
        severity: 'medium',
        title: 'Test Notification',
        message: 'This is a test notification from Rinjani CTI Platform.',
    });

    return c.json({ success: result.success, error: result.error });
});

/** POST /notifications/test/teams — Phase 4 #1 — verify a Teams Incoming Webhook URL */
notifications.post('/test/teams', requireAuth, async (c) => {
    const { webhookUrl } = TestChannelWebhookSchema.parse(await c.req.json());
    const result = await sendTeamsNotification(webhookUrl, {
        type: 'alert', severity: 'medium',
        title: 'Test Notification',
        message: 'This is a test notification from Rinjani CTI Platform.',
    });
    return c.json({ success: result.success, error: result.error });
});

/** POST /notifications/test/discord — verify a Discord Webhook URL */
notifications.post('/test/discord', requireAuth, async (c) => {
    const { webhookUrl } = TestChannelWebhookSchema.parse(await c.req.json());
    const result = await sendDiscordNotification(webhookUrl, {
        type: 'alert', severity: 'medium',
        title: 'Test Notification',
        message: 'This is a test notification from Rinjani CTI Platform.',
    });
    return c.json({ success: result.success, error: result.error });
});

/** POST /notifications/test/pagerduty — verify a PagerDuty Events API routing key */
notifications.post('/test/pagerduty', requireAuth, async (c) => {
    const { webhookUrl: routingKey } = TestChannelWebhookSchema.parse(await c.req.json());
    const result = await sendPagerDutyNotification(routingKey, {
        type: 'alert', severity: 'medium',
        title: 'Test Notification',
        message: 'This is a test notification from Rinjani CTI Platform.',
        data: { dedupKey: `test-${Date.now()}` },
    });
    return c.json({ success: result.success, error: result.error });
});

// ============================================================================
// Phase 4 #1 — Rule-based routing (DSL)
// ============================================================================

/**
 * POST /notifications/evaluate-rules
 *
 * Dry-run a list of routing rules against a payload. Returns the matched
 * (channel, target) pairs WITHOUT firing them — so analysts can sanity-
 * check a rule like `severity=critical AND inKev=true → PagerDuty`
 * before turning it on.
 */
notifications.post('/evaluate-rules', requireAuth, async (c) => {
    const { rules, payload } = EvaluateRulesSchema.parse(await c.req.json());
    const matched = resolveRuleChannels(rules, payload);
    return c.json({ success: true, data: { matched, count: matched.length } });
});

/**
 * POST /notifications/dispatch
 *
 * The "real" version: evaluate rules against a payload AND actually
 * fire the matched channels. Returns per-channel success/error. Used
 * by playbook actions + manual triggers.
 */
notifications.post('/dispatch', requireAuth, async (c) => {
    const { rules, payload } = EvaluateRulesSchema.parse(await c.req.json());
    const matched = resolveRuleChannels(rules, payload);

    const results = await dispatchToChannels(matched, payload, {
        slack: sendSlackNotification,
        teams: sendTeamsNotification,
        discord: sendDiscordNotification,
        pagerduty: sendPagerDutyNotification,
        email: sendEmailNotification,
    });

    const ok = results.every(r => r.result.success);
    return c.json({ success: ok, data: { matched: matched.length, results } }, ok ? 200 : 207);
});

// ============================================================================
// Manual Alert Triggers
// ============================================================================

/**
 * POST /notifications/alert
 * Manually trigger an alert broadcast
 */
notifications.post('/alert', requireAuth, async (c) => {
    const { type, severity, title, message, data } = ManualAlertSchema.parse(await c.req.json());

    const result = await broadcastNotification({
        type,
        severity,
        title,
        message,
        data,
    });

    return c.json({
        success: true,
        data: {
            sent: result.sent,
            failed: result.failed,
            errors: result.errors,
        },
    });
});

/**
 * GET /notifications/history
 * Get notification history (last 100)
 */
notifications.get('/history', requireAuth, async (c) => {
    try {
        const userId = c.req.header('X-User-Id') || 'default';
        const { limit } = (await import('../lib/schemas')).LimitSchema.parse(c.req.query());

        const history = await db.execute(sql`
            SELECT * FROM notification_logs 
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${limit}
        `) as unknown as Record<string, unknown>[];

        return c.json({
            success: true,
            data: {
                logs: history,
                total: history.length
            }
        });
    } catch (error) {
        // Table might not exist yet, return empty
        return c.json({
            success: true,
            data: { logs: [], total: 0 }
        });
    }
});

export default notifications;
