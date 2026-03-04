/**
 * Streaming Intelligence Routes — Barrel
 *
 * Mounts sub-routers:
 *   - streaming/streams.ts    → SSE endpoints (intel, social, campaign)
 *   - streaming/management.ts → subscribe, status
 *
 * SSE boilerplate eliminated via streaming/sseHelper.ts
 */

import { Hono } from 'hono';
import streamEndpoints from './streaming/streams';
import managementRoutes from './streaming/management';

const streamRoutes = new Hono();

streamRoutes.route('/', streamEndpoints);
streamRoutes.route('/', managementRoutes);

export default streamRoutes;
