/**
 * Web Intelligence Persistence Service — Barrel
 *
 * Sub-modules:
 *   - webIntelPersist/types.ts    → Type definitions
 *   - webIntelPersist/helpers.ts  → Platform detection
 *   - webIntelPersist/persist.ts  → Synchronous PostgreSQL save
 *   - webIntelPersist/postSave.ts → Background processing (OpenSearch + Neo4j)
 */

export type { ScrapeData, SaveResult } from './webIntelPersist/types';
export { saveScrapeResult } from './webIntelPersist/persist';
export { processPostSave } from './webIntelPersist/postSave';
export { detectPlatform } from './webIntelPersist/helpers';
export { backfillMentions } from './webIntelPersist/backfillMentions';
