/**
 * Exa AI — Monitors & Webhooks
 */

import { createLogger } from '../../lib/logger';
import { getExa, WEBSET_TEMPLATES } from './client';
import type { WebsetCategory } from './client';

const log = createLogger('Exa:monitors');

/**
 * Create a monitor on a webset for continuous updates.
 */
export async function createMonitor(
    websetId: string,
    category: WebsetCategory,
    cronExpression: string = '0 */6 * * *',
    timezone: string = 'Asia/Jakarta',
) {
    const exa = getExa();
    const template = WEBSET_TEMPLATES[category];

    const monitor = await exa.websets.monitors.create({
        websetId,
        cadence: { cron: cronExpression, timezone },
        behavior: {
            type: 'search',
            config: {
                query: template.search.query,
                criteria: template.search.criteria,
                count: Math.min(template.search.count, 25),
                behavior: 'append' as unknown as import('exa-js').WebsetSearchBehavior,
            },
        },
        metadata: { category, platform: 'rinjani' },
    } as unknown as Parameters<typeof exa.websets.monitors.create>[0]);

    log.info('Monitor created', { websetId, monitorId: monitor.id, cron: cronExpression });
    return monitor;
}

/**
 * Register a webhook to receive Exa push events.
 */
export async function registerWebhook(
    url: string,
    events: string[] = ['webset.item.created', 'webset.item.enriched', 'webset.search.completed', 'webset.idle'],
) {
    const exa = getExa();

    const webhook = await exa.websets.webhooks.create({
        url,
        events: events as unknown as import('exa-js').EventType[],
        metadata: { platform: 'rinjani' },
    });

    log.info('Webhook registered', { webhookId: webhook.id });
    return webhook;
}
