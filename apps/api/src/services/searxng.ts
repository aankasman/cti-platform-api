/**
 * SearXNG Search Service — Barrel
 *
 * Sub-modules:
 *   - searxng/types.ts   → Types & configuration
 *   - searxng/client.ts  → API client & result normalization
 *   - searxng/search.ts  → Search functions (web, news, social, IT)
 *   - searxng/scraper.ts → Content scraping, HTML utils, health check
 */

export type { SearXNGResult, SearXNGResponse, SearchOptions, NexusSearchResult } from './searxng/types';
export { searchWeb, searchNews, searchSocial, searchIT } from './searxng/search';
export { scrapeAndExtract, checkHealth } from './searxng/scraper';
