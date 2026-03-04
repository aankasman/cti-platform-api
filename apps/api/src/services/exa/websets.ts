/**
 * Exa AI — Webset Management
 */

import { createLogger } from '../../lib/logger';
import { getExa, WEBSET_TEMPLATES } from './client';
import type { WebsetCategory } from './client';

const log = createLogger('Exa:websets');

/**
 * Create a new Exa Webset from a predefined CTI category template.
 */
export async function createWebset(category: WebsetCategory): Promise<{ id: string; status: string;[key: string]: unknown }> {
    const exa = getExa();
    const template = WEBSET_TEMPLATES[category];
    if (!template) throw new Error(`Unknown webset category: ${category}`);

    const webset = await exa.websets.create({
        search: template.search,
        enrichments: template.enrichments as unknown as Record<string, unknown>[],
        metadata: { category, platform: 'rinjani', createdBy: 'phase44' },
    } as Record<string, unknown>);

    log.info('Webset created', { title: template.title, websetId: webset.id });
    return webset;
}

/**
 * List all websets.
 */
export async function listWebsets(): Promise<{ data: Array<{ id: string;[key: string]: unknown }>;[key: string]: unknown }> {
    const exa = getExa();
    return exa.websets.list();
}

/**
 * Get a single webset by ID.
 */
export async function getWebset(websetId: string): Promise<{ id: string; status: string;[key: string]: unknown }> {
    const exa = getExa();
    return exa.websets.get(websetId);
}

/**
 * Delete a webset.
 */
export async function deleteWebset(websetId: string): Promise<{ [key: string]: unknown }> {
    const exa = getExa();
    return exa.websets.delete(websetId);
}

/**
 * List items in a webset (paginated via cursor).
 */
export async function listWebsetItems(websetId: string, opts?: { limit?: number; cursor?: string }): Promise<{ data: Array<{ id: string; title?: string; url?: string; sourceUrl?: string; publishedDate?: string; contents?: { text?: string; summary?: string; highlights?: string[] }; enrichmentResults?: Record<string, unknown>;[key: string]: unknown }>; hasMore?: boolean; cursor?: string }> {
    const exa = getExa();
    return exa.websets.items.list(websetId, {
        limit: opts?.limit || 50,
        ...(opts?.cursor ? { cursor: opts.cursor } : {}),
    });
}

/**
 * Wait for a webset to finish processing and become idle.
 */
export async function waitForWebset(websetId: string, timeoutMs: number = 120000): Promise<{ id: string; status: string;[key: string]: unknown }> {
    const exa = getExa();
    return exa.websets.waitUntilIdle(websetId, {
        timeout: timeoutMs,
        pollInterval: 3000,
        onPoll: (status: string) => log.info('Webset poll', { websetId, status }),
    });
}
