/**
 * Admin Stream Info Routes
 *
 * Provides visibility into Redis Streams event system:
 * stream lengths, consumer group lag, pending messages.
 *
 * Mounts at: /admin/streams/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../../../middleware/auth';
import { eventStream } from '../../../../services/eventStream';
import { AdminStreamClaimSchema } from '../../../../lib/schemas';

const router = new Hono();

/** GET /streams — Stream and consumer group overview */
router.get('/streams', requireAuth, requireRole('admin'), async (c) => {
    const info = await eventStream.getStreamInfo();

    // Transform Record<string, {...}> → StreamInfo[] (frontend expects an array with name)
    const arr = Object.entries(info).map(([name, v]) => ({ name, ...v }));

    return c.json({
        success: true,
        data: arr,
    });
});

/** POST /streams/:stream/claim — Claim pending (stuck) messages */
router.post('/streams/:stream/claim', requireAuth, requireRole('admin'), async (c) => {
    const stream = c.req.param('stream') as import('../../../../services/eventStream').StreamName;
    const { group, consumer, minIdleMs } = AdminStreamClaimSchema.parse(c.req.query());

    const claimed = await eventStream.claimPending(stream, group, consumer, minIdleMs);

    return c.json({
        success: true,
        data: { stream, group, claimed },
    });
});

export default router;
