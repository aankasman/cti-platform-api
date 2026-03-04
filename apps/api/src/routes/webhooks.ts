/**
 * Webhook API Routes
 * 
 * Management API for webhook subscriptions.
 */

import { Hono } from 'hono';
import {
    registerSubscription,
    unregisterSubscription,
    getSubscriptions,
    getSubscription,
    emitWebhookEvent,
    WEBHOOK_EVENTS
} from '@rinjani/core/webhooks';
import { requireAuth, requireRole } from '../middleware/auth';
import { NotFoundError } from '../lib/errors';
import { CreateWebhookSchema } from '../lib/schemas';

export const webhookRouter = new Hono();

// Require authentication for all webhook routes
webhookRouter.use('*', requireAuth);

// ============================================================================
// Subscription Management
// ============================================================================

/**
 * GET /v1/webhooks
 * List all webhook subscriptions
 */
webhookRouter.get('/', (c) => {
    const subs = getSubscriptions();

    // Hide secrets from response
    const sanitized = subs.map((s: { id: string; url: string; secret?: string | null }) => ({
        ...s,
        secret: s.secret ? '********' : null,
    }));


    return c.json({
        success: true,
        data: {
            subscriptions: sanitized,
            count: sanitized.length,
        },
    });
});

/**
 * GET /v1/webhooks/:id
 * Get a single webhook subscription
 */
webhookRouter.get('/:id', (c) => {
    const { id } = c.req.param();
    const sub = getSubscription(id);

    if (!sub) {
        throw new NotFoundError('Subscription', id);
    }

    return c.json({
        success: true,
        data: {
            ...sub,
            secret: sub.secret ? '********' : null,
        },
    });
});

/**
 * POST /v1/webhooks
 * Create a new webhook subscription
 */
webhookRouter.post('/', requireRole('admin', 'analyst'), async (c) => {
    const body = CreateWebhookSchema.parse(await c.req.json());

    const id = crypto.randomUUID();
    const subscription = {
        id,
        name: body.name,
        url: body.url,
        secret: body.secret ?? null,
        events: body.events,
        filters: body.filters,
        headers: body.headers,
    };

    registerSubscription(subscription);

    return c.json({
        success: true,
        data: {
            id,
            message: 'Webhook subscription created',
            subscription: {
                ...subscription,
                secret: subscription.secret ? '********' : null,
            },
        },
    }, 201);
});

/**
 * DELETE /v1/webhooks/:id
 * Delete a webhook subscription
 */
webhookRouter.delete('/:id', requireRole('admin'), (c) => {
    const { id } = c.req.param();

    if (!getSubscription(id)) {
        throw new NotFoundError('Subscription', id);
    }

    unregisterSubscription(id);

    return c.json({
        success: true,
        message: 'Webhook subscription deleted',
    });
});

/**
 * POST /v1/webhooks/:id/test
 * Send a test event to a webhook
 */
webhookRouter.post('/:id/test', requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const sub = getSubscription(id);

    if (!sub) {
        throw new NotFoundError('Subscription', id);
    }

    // Temporarily register for test
    registerSubscription({
        ...sub,
        events: ['test.ping'],
    });

    const result = await emitWebhookEvent('test.ping', {
        message: 'This is a test webhook event from RinjaniAnalytics',
        timestamp: new Date().toISOString(),
    });

    // Restore original events
    registerSubscription(sub);

    return c.json({
        success: result.delivered > 0,
        data: {
            delivered: result.delivered,
            failed: result.failed,
        },
    });
});

// ============================================================================
// Event Info
// ============================================================================

/**
 * GET /v1/webhooks/events
 * List available webhook event types
 */
webhookRouter.get('/events', (c) => {
    return c.json({
        success: true,
        data: {
            events: Object.entries(WEBHOOK_EVENTS).map(([key, value]) => ({
                name: key,
                type: value,
            })),
            wildcards: [
                { pattern: '*', description: 'All events' },
                { pattern: 'ioc.*', description: 'All IOC events' },
                { pattern: 'vulnerability.*', description: 'All vulnerability events' },
                { pattern: 'threat_actor.*', description: 'All threat actor events' },
                { pattern: 'feed.*', description: 'All feed sync events' },
                { pattern: 'alert.*', description: 'All alert events' },
            ],
        },
    });
});

export default webhookRouter;
