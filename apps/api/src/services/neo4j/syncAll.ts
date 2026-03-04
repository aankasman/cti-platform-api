/**
 * Neo4j Full Sync — Barrel
 *
 * Sub-modules:
 *   - syncAll/orchestrator.ts  → Full sync coordinator
 *   - syncAll/webIntelSync.ts  → Web intelligence items → WebSource nodes
 *   - syncAll/campaignSync.ts  → Campaigns → Campaign nodes + edges
 */

export type { Neo4jSyncResult } from './syncAll/orchestrator';
export { syncAllToNeo4j } from './syncAll/orchestrator';
export { syncWebIntelToNeo4j } from './syncAll/webIntelSync';
export { syncCampaignsToNeo4j } from './syncAll/campaignSync';
