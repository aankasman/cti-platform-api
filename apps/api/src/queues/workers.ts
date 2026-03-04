/**
 * BullMQ Workers — Barrel Re-export
 *
 * Background workers that process jobs from queues.
 * Uses structured JSON logging via lib/logger.
 */

// Feed sync + IOC enrichment workers
export { feedSyncWorker, enrichmentWorker } from './workers/feedWorkers';

// AI analysis + notification + alerts workers
export { aiAnalysisWorker, notificationWorker, alertsWorker, alertStore } from './workers/utilityWorkers';

// Neo4j sync + Nexus intelligence workers
export { neo4jSyncWorker, nexusWorker } from './workers/syncWorkers';

// CVE enrichment worker
export { cveEnrichmentWorker } from './workers/cveEnrichmentWorker';

// Data lifecycle + maintenance worker
export { retentionWorker } from './workers/retentionWorker';

// Event handlers + startup/shutdown
export { startWorkers, stopWorkers } from './workers/workerEvents';
