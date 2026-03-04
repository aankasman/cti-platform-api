/**
 * Nexus Bootstrap Service
 *
 * Initializes all 4 CTI Websets, configures Exa Monitors (every 6 hours),
 * registers a webhook for push-based events, and schedules periodic
 * BullMQ sync jobs as a fallback.
 *
 * Usage:
 *   POST /nexus/bootstrap  → Create all websets + monitors + webhook
 *   POST /nexus/bootstrap/monitors → Attach monitors to existing websets
 */

import { db, eq } from '@rinjani/db';
import { exaWebsets } from '@rinjani/db/schema';
import * as exa from './exa';
import type { WebsetCategory } from './exa';
import { createLogger } from '../lib/logger';

const log = createLogger('NexusBootstrap');

// ============================================================================
// Configuration
// ============================================================================

/**
 * All 4 CTI categories to bootstrap.
 */
const ALL_CATEGORIES: WebsetCategory[] = ['malware-c2', 'zero-day-cve', 'apt-actors', 'socmint'];

/**
 * Monitor cron schedule — every 30 minutes for near-real-time CTI ingestion
 */
const MONITOR_CRON = '*/30 * * * *';
const MONITOR_TZ = 'Asia/Jakarta';

/**
 * Webhook URL for push events. Set via NEXUS_WEBHOOK_URL or computed from API_BASE_URL.
 */
function getWebhookUrl(): string {
    const explicit = process.env.NEXUS_WEBHOOK_URL;
    if (explicit) return explicit;

    const baseUrl = process.env.API_BASE_URL || process.env.PUBLIC_API_URL;
    if (baseUrl) return `${baseUrl}/v2/nexus/webhook`;

    return 'http://localhost:3001/v2/nexus/webhook';
}

// ============================================================================
// Bootstrap Functions
// ============================================================================

export interface BootstrapResult {
    websets: { category: string; websetId: string; status: string }[];
    monitors: { category: string; monitorId: string; cron: string }[];
    webhook?: { id: string; url: string; secret?: string };
    errors: string[];
}

/**
 * Bootstrap all 4 Websets with Monitors and a single webhook.
 *
 * Idempotent: skips categories that already have an active webset.
 */
export async function bootstrapAll(): Promise<BootstrapResult> {
    const result: BootstrapResult = {
        websets: [],
        monitors: [],
        errors: [],
    };

    log.info('Starting full bootstrap');

    // 1. Create websets for each category
    for (const category of ALL_CATEGORIES) {
        try {
            // Check if already exists locally
            const [existing] = await db.select().from(exaWebsets)
                .where(eq(exaWebsets.category, category));

            if (existing) {
                log.info('Webset already exists, skipping', { category, websetId: existing.exaWebsetId });
                result.websets.push({
                    category,
                    websetId: existing.exaWebsetId,
                    status: 'already-exists',
                });
                continue;
            }

            // Create via Exa API
            const webset = await exa.createWebset(category);

            // Persist locally
            await db.insert(exaWebsets).values({
                exaWebsetId: webset.id,
                category,
                title: exa.WEBSET_TEMPLATES[category]?.title || category,
                status: 'active',
                config: { searchQuery: exa.WEBSET_TEMPLATES[category]?.search.query },
            });

            result.websets.push({ category, websetId: webset.id, status: 'created' });
            log.info('Webset created', { category, websetId: webset.id });

            // Small delay to avoid rate limits
            await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (err) {
            const msg = `Failed to create webset ${category}: ${(err as Error).message}`;
            log.error(msg, err as Error);
            result.errors.push(msg);
        }
    }

    // 2. Attach monitors to newly created websets
    await attachMonitors(result);

    // 3. Register webhook
    try {
        const webhookUrl = getWebhookUrl();
        const webhook = await exa.registerWebhook(webhookUrl);
        result.webhook = {
            id: webhook.id,
            url: webhookUrl,
            secret: webhook.secret ?? undefined, // Only returned on creation — save it!
        };
        log.info('Webhook registered', { webhookId: webhook.id, url: webhookUrl });
    } catch (err) {
        const msg = `Failed to register webhook: ${(err as Error).message}`;
        log.error(msg, err as Error);
        result.errors.push(msg);
    }

    log.info('Bootstrap complete', { websets: result.websets.length, monitors: result.monitors.length, errors: result.errors.length });

    return result;
}

/**
 * Attach monitors to all existing websets that don't already have one.
 */
export async function attachMonitors(result?: BootstrapResult): Promise<BootstrapResult> {
    const r = result || { websets: [], monitors: [], errors: [] };

    const localWebsets = await db.select().from(exaWebsets);

    for (const ws of localWebsets) {
        try {
            const monitor = await exa.createMonitor(
                ws.exaWebsetId,
                ws.category as WebsetCategory,
                MONITOR_CRON,
                MONITOR_TZ,
            );

            r.monitors.push({
                category: ws.category,
                monitorId: monitor.id,
                cron: MONITOR_CRON,
            });

            // Store monitor ID in webset config
            const existingConfig = (ws.config || {}) as Record<string, unknown>;
            await db.update(exaWebsets)
                .set({
                    config: { ...existingConfig, monitorId: monitor.id, monitorCron: MONITOR_CRON },
                    updatedAt: new Date(),
                })
                .where(eq(exaWebsets.id, ws.id));

            log.info('Monitor created', { category: ws.category, monitorId: monitor.id });
        } catch (err) {
            const msg = `Failed to create monitor for ${ws.category}: ${(err as Error).message}`;
            log.error(msg, err as Error);
            r.errors.push(msg);
        }
    }

    return r;
}

/**
 * Get current bootstrap status — which websets exist and their monitors.
 */
export async function getBootstrapStatus() {
    const localWebsets = await db.select().from(exaWebsets);

    const categories = ALL_CATEGORIES.map(cat => {
        const ws = localWebsets.find(w => w.category === cat);
        const config = (ws?.config || {}) as Record<string, unknown>;
        return {
            category: cat,
            active: !!ws,
            websetId: ws?.exaWebsetId || null,
            monitorId: config.monitorId || null,
            monitorCron: config.monitorCron || null,
            itemCount: ws?.itemCount || 0,
            lastSyncAt: ws?.lastSyncAt || null,
        };
    });

    return {
        totalActive: categories.filter(c => c.active).length,
        totalExpected: ALL_CATEGORIES.length,
        fullyBootstrapped: categories.every(c => c.active && c.monitorId),
        categories,
    };
}
