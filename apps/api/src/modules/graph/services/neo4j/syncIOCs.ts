/**
 * Neo4j IOC Sync — Barrel
 *
 * Sub-modules:
 *   - syncIOCs/pulseSync.ts      → Pulses + IOCs + attribution edges
 *   - syncIOCs/cveSync.ts        → CVE nodes
 *   - syncIOCs/batchSync.ts      → ALL IOCs (batch processing)
 *   - syncIOCs/similaritySync.ts → Embedding similarity links (k-NN)
 */

export { syncPulsesAndIOCs } from './syncIOCs/pulseSync';
export { syncCVEs } from './syncIOCs/cveSync';
export { syncAllIOCs } from './syncIOCs/batchSync';
export { syncSimilarIOCs } from './syncIOCs/similaritySync';
