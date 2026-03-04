/**
 * Exa AI Intelligence Service — Barrel
 *
 * Sub-modules:
 *   - exa/client.ts   → Client singleton, templates, categories, health
 *   - exa/websets.ts  → Webset CRUD operations
 *   - exa/search.ts   → Real-time Search API
 *   - exa/monitors.ts → Monitors & webhooks
 */

export { getExa, WEBSET_TEMPLATES, getWebsetCategories, checkHealth } from './exa/client';
export type { WebsetCategory } from './exa/client';
export { createWebset, listWebsets, getWebset, deleteWebset, listWebsetItems, waitForWebset } from './exa/websets';
export { searchWeb, searchThreats } from './exa/search';
export type { ExaSearchOptions } from './exa/search';
export { createMonitor, registerWebhook } from './exa/monitors';
