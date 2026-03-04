/**
 * n8n SOAR Routes — Workflow Automation Proxy
 *
 * Proxies n8n API requests through the Rinjani backend so the dashboard
 * doesn't need direct access to n8n. Also provides a webhook trigger
 * endpoint for manual SOAR execution.
 */

import { Hono } from 'hono';
import { n8nClient } from '../../../services/n8n';

const n8n = new Hono();

// ============================================================================
// GET /n8n/workflows — list active n8n workflows
// ============================================================================
n8n.get('/n8n/workflows', async (c) => {
    const workflows = await n8nClient.getWorkflows();
    return c.json({ data: workflows });
});

// ============================================================================
// GET /n8n/executions?limit=20 — recent workflow executions
// ============================================================================
n8n.get('/n8n/executions', async (c) => {
    const limit = parseInt(c.req.query('limit') || '20', 10);
    const executions = await n8nClient.getExecutions(limit);
    return c.json({ data: executions });
});

// ============================================================================
// GET /n8n/status — n8n availability check
// ============================================================================
n8n.get('/n8n/status', async (c) => {
    n8nClient.resetAvailability();
    const available = await n8nClient.isAvailable();
    return c.json({ data: { available } });
});

// ============================================================================
// POST /n8n/trigger/:webhook — trigger an n8n webhook with payload
// ============================================================================
n8n.post('/n8n/trigger/:webhook', async (c) => {
    const webhookPath = c.req.param('webhook');
    const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
    const ok = await n8nClient.triggerWebhook(webhookPath, body);
    return c.json({
        data: { success: ok, message: ok ? 'Webhook triggered' : 'n8n unavailable or webhook failed' },
    }, ok ? 200 : 503);
});

export default n8n;
