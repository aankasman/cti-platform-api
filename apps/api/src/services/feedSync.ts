/**
 * Feed Sync Service — Barrel
 *
 * Sub-modules:
 *   - feedSync/types.ts     → Type definitions
 *   - feedSync/otxClient.ts → OTX API client & delta helpers
 *   - feedSync/otxSync.ts   → OTX feed sync
 *   - feedSync/cisaSync.ts  → CISA KEV sync
 *   - feedSync/nvdSync.ts   → NVD sync (placeholder)
 */

export type { OTXPulse, OTXIndicator, OTXSyncOptions, SyncResult, CISAVulnerability } from './feedSync/types';
export { mapOTXType, otxFetch, getExistingIOCValues, getExistingPulseIds } from './feedSync/otxClient';
export { syncOTXFeed, fetchSubscribedPulses } from './feedSync/otxSync';
export { syncCISAFeed } from './feedSync/cisaSync';
export { syncNVDFeed } from './feedSync/nvdSync';
export { getFeedHandler, getRegisteredFeeds, isFeedRegistered } from './feedSync/feedRegistry';
