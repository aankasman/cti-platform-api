/**
 * Nexus Webset Routes
 *
 * CRUD for Exa Websets, item listing, sync, deletion, webhook receiver.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { db, eq } from '@rinjani/db';
import { exaWebsets } from '@rinjani/db/schema';
import * as exa from '../../services/exa';
import { nexusQueue } from '../../queues';
import { ValidationError, NotFoundError } from '../../lib/errors';
import { LimitSchema } from '../../lib/schemas';
import { createLogger } from '../../lib/logger';
import { CreateWebsetSchema } from './schemas';
import { bootstrapAll, attachMonitors, getBootstrapStatus } from '../../services/nexusBootstrap';

const router = new Hono();
const log = createLogger('Nexus:websets');

// ============================================================================
// Webset CRUD
// ============================================================================

/** GET /categories - List available CTI category templates */
router.get('/categories', (c: Context) => {
    return c.json({
        success: true,
        data: exa.getWebsetCategories(),
    });
});

/** POST /websets - Create a new Webset from a category template */
router.post('/websets', async (c: Context) => {
    const body = await c.req.json();
    const parsed = CreateWebsetSchema.safeParse(body);
    if (!parsed.success) {
        throw new ValidationError(
            parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
        );
    }
    const { category } = parsed.data;

    const webset = await exa.createWebset(category);

    // Store in our database
    await db.insert(exaWebsets).values({
        exaWebsetId: webset.id,
        category,
        title: exa.WEBSET_TEMPLATES[category]?.title || category,
        status: 'active',
        config: { searchQuery: exa.WEBSET_TEMPLATES[category]?.search.query },
    });

    return c.json({
        success: true,
        data: {
            id: webset.id,
            category,
            status: webset.status,
            message: `Webset created. It will take a few minutes to discover items.`,
        },
    });
});

/** GET /websets - List all tracked Websets */
router.get('/websets', async (c: Context) => {
    const localWebsets = await db.select().from(exaWebsets).orderBy(exaWebsets.createdAt);
    return c.json({ success: true, data: localWebsets });
});

/** GET /websets/:id - Get Webset details (live) */
router.get('/websets/:id', async (c: Context) => {
    const websetId = c.req.param('id');
    const webset = await exa.getWebset(websetId);
    return c.json({ success: true, data: webset });
});

/** GET /websets/:id/items - List items in a Webset */
router.get('/websets/:id/items', async (c: Context) => {
    const websetId = c.req.param('id');
    const { limit } = LimitSchema.parse(c.req.query());
    const cursor = c.req.query('cursor');

    const items = await exa.listWebsetItems(websetId, { limit, cursor });
    return c.json({ success: true, data: items });
});

/** POST /websets/:id/sync - Queue background sync of Webset items */
router.post('/websets/:id/sync', async (c: Context) => {
    const exaWebsetId = c.req.param('id');

    // Verify the webset is tracked locally
    const [localWebset] = await db.select().from(exaWebsets)
        .where(eq(exaWebsets.exaWebsetId, exaWebsetId));

    if (!localWebset) {
        throw new NotFoundError(`Webset ${exaWebsetId} not tracked locally. Create it first via POST /nexus/websets.`);
    }

    // Queue background sync job
    const job = await nexusQueue.add(`sync-${exaWebsetId}`, {
        type: 'sync-webset',
        websetId: exaWebsetId,
        category: localWebset.category,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            websetId: exaWebsetId,
            message: 'Sync job queued. Use GET /v1/queues/stats to track progress.',
            queuedAt: new Date().toISOString(),
        },
    });
});

/** DELETE /websets/:id - Delete a Webset */
router.delete('/websets/:id', async (c: Context) => {
    const websetId = c.req.param('id');

    await exa.deleteWebset(websetId);

    // Remove from local DB
    await db.delete(exaWebsets)
        .where(eq(exaWebsets.exaWebsetId, websetId));

    return c.json({ success: true, message: 'Webset deleted' });
});

// ============================================================================
// Webhook Receiver
// ============================================================================

/** POST /webhook - Receive events from intelligence webhooks */
router.post('/webhook', async (c: Context) => {
    const event = await c.req.json();
    const eventType = event.type || 'unknown';

    log.info('Webhook received', { eventType });

    switch (eventType) {
        case 'webset.item.created': {
            const item = event.data;
            if (item) {
                await nexusQueue.add(`webhook-${item.id || Date.now()}`, {
                    type: 'webhook-item',
                    websetId: item.websetId,
                    itemId: item.id,
                    payload: item,
                });
            }
            break;
        }

        case 'webset.idle':
        case 'webset.search.completed':
            log.debug('Webset operation completed', { eventType });
            break;

        default:
            log.debug('Unhandled event type', { eventType });
    }

    // Always ACK immediately — processing happens in the background
    return c.json({ success: true, received: eventType });
});

// ============================================================================
// Bootstrap (Admin)
// ============================================================================

/** POST /bootstrap - One-click setup: create all 4 Websets + Monitors + Webhook */
router.post('/bootstrap', async (c: Context) => {
    const result = await bootstrapAll();
    return c.json({ success: true, data: result });
});

/** POST /bootstrap/monitors - Attach Monitors to all existing Websets */
router.post('/bootstrap/monitors', async (c: Context) => {
    const result = await attachMonitors();
    return c.json({ success: true, data: result });
});

/** GET /bootstrap/status - Check which Websets and Monitors are active */
router.get('/bootstrap/status', async (c: Context) => {
    const status = await getBootstrapStatus();
    return c.json({ success: true, data: status });
});

export default router;
