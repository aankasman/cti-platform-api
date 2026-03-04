/**
 * Operations Monitoring Routes
 *
 * Infrastructure health, ingestion rates, enrichment performance,
 * and worker metrics. All logic decomposed into sub-modules under ./ops/.
 */

import { Hono } from 'hono';
import systemRoutes from './ops/system';
import ingestionRoutes from './ops/ingestion';
import enrichmentRoutes from './ops/enrichment';
import workerRoutes from './ops/workers';
import embeddingRoutes from './ops/embedding';
import prometheusRoutes from './ops/prometheus';

export const opsRouter = new Hono();

// Infrastructure health
opsRouter.route('/', systemRoutes);

// IOC ingestion rates
opsRouter.route('/', ingestionRoutes);

// Enrichment queue metrics
opsRouter.route('/', enrichmentRoutes);

// Worker throughput
opsRouter.route('/', workerRoutes);

// Embedding & reindex progress
opsRouter.route('/', embeddingRoutes);

// Prometheus scrape endpoint
opsRouter.route('/', prometheusRoutes);

export default opsRouter;
