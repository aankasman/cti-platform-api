/**
 * Monitoring Routes — Barrel
 *
 * Provides feed health monitoring, system metrics, and alerting capabilities.
 */

import { Hono } from 'hono';
import feedRoutes from './monitoring/feeds';
import healthRoutes from './monitoring/health';
import metricsRoutes from './monitoring/metrics';

const monitoring = new Hono();

monitoring.route('/', feedRoutes);
monitoring.route('/', healthRoutes);
monitoring.route('/', metricsRoutes);

export default monitoring;
