/**
 * SSE Stream Endpoints
 *
 * Uses the shared createSSEStream helper to eliminate boilerplate.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { createSSEStream } from './sseHelper';

const streamEndpoints = new Hono();

/**
 * GET /intel - Live SSE feed of all web intelligence items
 */
streamEndpoints.get('/intel', async (c: Context) => {
    return createSSEStream(c, ['webint', 'iocs', 'vulnerabilities'], 'Nexus Intelligence Stream', 'intel');
});

/**
 * GET /social - SSE feed filtered to SOCMINT sources
 */
streamEndpoints.get('/social', async (c: Context) => {
    return createSSEStream(c, ['socmint'], 'Social Intelligence Stream', 'social');
});

/**
 * GET /campaign - Campaign activity updates
 */
streamEndpoints.get('/campaign', async (c: Context) => {
    return createSSEStream(c, ['campaign'], 'Campaign Activity Stream', 'campaign');
});

export default streamEndpoints;
