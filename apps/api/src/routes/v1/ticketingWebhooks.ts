/**
 * Ticketing inbound webhook routes (Phase 4 #6b).
 *
 *   POST /v1/webhooks/github/issues
 *
 * Unauthenticated by Bearer/API key — authenticity is proven by the
 * HMAC-SHA256 signature GitHub sends in `X-Hub-Signature-256`. Without
 * `GITHUB_WEBHOOK_SECRET` configured the route returns 503 (we refuse
 * to process unsigned payloads even in dev).
 */
import { Hono } from 'hono';
import { applyGithubWebhook, verifyGithubSignature } from '../../services/ticketing/webhooks';
import { createLogger } from '../../lib/logger';

const log = createLogger('GHWebhookRoute');

const router = new Hono();

router.post('/webhooks/github/issues', async (c) => {
    const secret = process.env.GITHUB_WEBHOOK_SECRET?.trim();
    if (!secret) {
        return c.json({ success: false, error: 'GITHUB_WEBHOOK_SECRET not configured' }, 503);
    }

    // Read raw body BEFORE JSON.parse so HMAC sees the exact bytes GitHub signed.
    const rawBody = await c.req.text();
    const signature = c.req.header('x-hub-signature-256');
    if (!verifyGithubSignature(rawBody, signature, secret)) {
        log.warn('webhook signature verification failed', {
            hasHeader: !!signature, bodyLen: rawBody.length,
        });
        return c.json({ success: false, error: 'invalid signature' }, 401);
    }

    const eventType = c.req.header('x-github-event') ?? '';

    let payload: unknown;
    try {
        payload = JSON.parse(rawBody);
    } catch (err) {
        return c.json({ success: false, error: 'invalid JSON payload' }, 400);
    }

    const outcome = await applyGithubWebhook(eventType, payload as never);
    return c.json({ success: true, data: outcome });
});

export default router;
