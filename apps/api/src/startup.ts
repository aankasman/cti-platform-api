/**
 * Background Service Bootstrap
 *
 * Starts all background services (scheduler, DB listener, workers,
 * web search worker, graceful shutdown handler, scheduled jobs).
 * Called once after the HTTP server starts.
 */

import { createLogger } from './lib/logger';

const log = createLogger('Boot');

export async function bootServices(): Promise<void> {
    // Run pending database migrations before anything else
    import('./services/migrations').then(({ autoMigrateOnStartup }) => {
        autoMigrateOnStartup();
    }).catch(err => {
        log.warn('Auto-migrate failed', { error: err.message });
    });

    // Ensure all built-in feeds, API keys, and services exist in config tables
    import('./services/configBootstrap').then(({ ensureBuiltInIntegrations }) => {
        ensureBuiltInIntegrations();
    }).catch(err => {
        log.warn('Config bootstrap failed', { error: err.message });
    });

    // Ensure all built-in roles (admin, analyst, developer, auditor, viewer) exist
    import('./services/userService').then(({ ensureBuiltInRoles }) => {
        ensureBuiltInRoles();
    }).catch(err => {
        log.warn('Role bootstrap failed', { error: err.message });
    });

    // ── Platform service availability checks (optional services) ──────────
    import('./services/vault').then(({ secrets }) => {
        secrets.isAvailable().then(ok => {
            log.info(`Vault: ${ok ? '✅ connected' : '⏭️  unavailable (using env vars)'}`);
        });
    }).catch(() => { /* vault module load failure — non-critical */ });

    import('./services/keycloak').then(({ keycloak }) => {
        keycloak.isAvailable().then(ok => {
            log.info(`Keycloak: ${ok ? '✅ connected' : '⏭️  unavailable (using API key auth)'}`);
        });
    }).catch(() => { /* keycloak module load failure — non-critical */ });

    import('./services/meilisearch').then(({ meiliSearch }) => {
        meiliSearch.isAvailable().then(ok => {
            if (ok) meiliSearch.setupIndex();
            log.info(`MeiliSearch: ${ok ? '✅ connected + index configured' : '⏭️  unavailable'}`);
        });
    }).catch(() => { /* meilisearch module load failure — non-critical */ });

    import('./services/n8n').then(({ n8nClient }) => {
        n8nClient.isAvailable().then((ok: boolean) => {
            log.info(`n8n: ${ok ? '✅ connected' : '⏭️  unavailable'}`);
        });
    }).catch(() => { /* n8n module load failure — non-critical */ });

    // Start SSE event bus (Redis Pub/Sub)
    import('./services/eventBus').then(({ eventBus }) => {
        eventBus.start();
    }).catch(err => {
        log.warn('EventBus failed to start', { error: err.message });
    });

    // Start Redis Streams event-driven architecture (durable event bus)
    Promise.all([
        import('./services/eventStream'),
        import('./queues/streamConsumers'),
    ]).then(([{ eventStream }, consumers]) => {
        eventStream.start().then(() => {
            // Register all consumer groups
            eventStream.startConsumer({
                group: 'enrichment-group',
                consumer: 'enrichment-1',
                streams: ['ioc'],
                handler: consumers.handleEnrichment,
                batchSize: 20,
            });

            eventStream.startConsumer({
                group: 'opensearch-group',
                consumer: 'opensearch-1',
                streams: ['ioc', 'vuln', 'actor', 'enrichment'],
                handler: consumers.handleOpenSearchSync,
                batchSize: 50,
            });

            eventStream.startConsumer({
                group: 'neo4j-group',
                consumer: 'neo4j-1',
                streams: ['ioc', 'vuln', 'actor'],
                handler: consumers.handleNeo4jSync,
                batchSize: 20,
            });

            eventStream.startConsumer({
                group: 'alert-group',
                consumer: 'alert-1',
                streams: ['ioc', 'enrichment'],
                handler: consumers.handleAlertEvaluation,
                batchSize: 50,
            });

            eventStream.startConsumer({
                group: 'taxii-group',
                consumer: 'taxii-1',
                streams: ['ioc', 'actor', 'enrichment'],
                handler: consumers.handleTaxiiPublish,
                batchSize: 30,
            });

            eventStream.startConsumer({
                group: 'meili-group',
                consumer: 'meili-1',
                streams: ['ioc', 'vuln', 'actor', 'enrichment'],
                handler: consumers.handleMeiliSync,
                batchSize: 50,
            });

            eventStream.startConsumer({
                group: 'n8n-group',
                consumer: 'n8n-1',
                streams: ['ioc', 'enrichment'],
                handler: consumers.handleN8nNotify,
                batchSize: 20,
            });

            // Audit trail — capture all entity events for audit_logs table
            eventStream.startConsumer({
                group: 'audit-group',
                consumer: 'audit-1',
                streams: ['ioc', 'vuln', 'actor', 'enrichment', 'system'],
                handler: consumers.handleAuditLog,
                batchSize: 50,
            });

            log.info('All stream consumers registered (8 groups)');
        });
    }).catch(err => {
        log.warn('EventStream failed to start', { error: err.message });
    });

    // Start background scheduler for periodic reindexing
    import('./services/scheduler').then(({ startScheduler }) => {
        startScheduler();
    }).catch(err => {
        log.warn('Scheduler failed to start', { error: err.message });
    });

    // Start PostgreSQL listener for real-time OpenSearch sync
    import('./services/db-listener').then(({ startDBListener }) => {
        startDBListener();
    }).catch(err => {
        log.warn('DB-Listener failed to start', { error: err.message });
    });

    // NOTE: BullMQ workers + WebSearchWorker have been extracted to
    // apps/worker/src/worker-entry.ts for independent scaling.
    // Run with: pnpm --filter @rinjani/worker start:workers

    // Graceful shutdown: close all DB + Redis connections on process signals
    Promise.all([
        import('./lib/db/clients'),
        import('./services/redis'),
        import('./services/eventBus'),
        import('./services/eventStream'),
    ]).then(([{ shutdownAll }, { shutdownRedis }, { eventBus }, { eventStream }]) => {
        const shutdown = async (signal: string) => {
            log.info(`Received ${signal}, shutting down gracefully...`);
            await Promise.allSettled([
                shutdownAll(),
                shutdownRedis(),
                eventBus.shutdown(),
                eventStream.shutdown(),
            ]);
            log.info('All connections closed, exiting');
            process.exit(0);
        };
        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));
    }).catch(err => {
        log.warn('Failed to setup graceful shutdown', { error: err.message });
    });

    // NOTE: Scheduled jobs (cron-like repeatable BullMQ jobs) have been
    // extracted to apps/worker/src/worker-entry.ts.
    // Run with: pnpm --filter @rinjani/worker start:workers

    // Register playbook evaluator as webhook event listener
    Promise.all([
        import('@rinjani/core/webhooks'),
        import('./services/playbooks'),
    ]).then(([{ addWebhookEventListener }, { evaluatePlaybooks }]) => {
        addWebhookEventListener(async (event, data) => {
            try {
                await evaluatePlaybooks(event, data);
            } catch (err) {
                log.warn('Playbook evaluation failed', { event, error: (err as Error).message });
            }
        });
        log.info('Playbook event listener registered');
    }).catch(err => {
        log.warn('Failed to register playbook event listener', { error: err.message });
    });
}
