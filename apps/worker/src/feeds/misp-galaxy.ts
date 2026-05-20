/**
 * MISP Galaxy Multi-Cluster Sync
 *
 * Fetches threat intelligence data from MISP Galaxy clusters (public, no API key).
 * Syncs the following cluster types:
 *
 *   ┌─────────────────────────┬───────────────────────────────────────────┐
 *   │ Cluster File            │ DB Target                                │
 *   ├─────────────────────────┼───────────────────────────────────────────┤
 *   │ threat-actor.json       │ threat_actors table (enrichment)         │
 *   │ malpedia.json           │ malware table                           │
 *   │ ransomware.json         │ malware table (type = ransomware)       │
 *   │ backdoor.json           │ malware table (type = backdoor)         │
 *   │ banker.json             │ malware table (type = banker)           │
 *   │ rat.json                │ malware table (type = rat)              │
 *   │ stealer.json            │ malware table (type = stealer)          │
 *   │ botnet.json             │ malware table (type = botnet)           │
 *   │ tool.json               │ galaxy_clusters table (type = tool)     │
 *   │ exploit-kit.json        │ galaxy_clusters table (type = exploit)  │
 *   │ sector.json             │ galaxy_clusters table (type = sector)   │
 *   │ country.json            │ galaxy_clusters table (type = country)  │
 *   │ threat-actor.json       │ threat_actors table (enrichment)        │
 *   │ microsoft-activity-group│ galaxy_clusters table (type = ms-group) │
 *   │ surveillance-vendor     │ galaxy_clusters table (type = surv)     │
 *   └─────────────────────────┴───────────────────────────────────────────┘
 *
 * Source: https://github.com/MISP/misp-galaxy (Public GitHub repository)
 */

import { db } from '@rinjani/db';
import { threatActors, malware, galaxyClusters, detectionRules, syncLogs } from '@rinjani/db/schema';
import { eq, and } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('MISPGalaxy');

const BASE = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters';

// =============================================================================
// Types
// =============================================================================

interface MISPClusterValue {
    value: string;
    description?: string;
    uuid: string;
    meta?: Record<string, unknown>;
}

interface MISPCluster {
    name: string;
    type: string;
    description: string;
    category: string;
    source: string;
    values: MISPClusterValue[];
    version: number;
}

// =============================================================================
// Cluster Definitions — what to sync and where to store it
// =============================================================================

/** Malware-type clusters → stored in the `malware` table */
const MALWARE_CLUSTERS = [
    { file: 'malpedia.json', malwareType: 'malware-family' },
    { file: 'ransomware.json', malwareType: 'ransomware' },
    { file: 'backdoor.json', malwareType: 'backdoor' },
    { file: 'banker.json', malwareType: 'banker' },
    { file: 'rat.json', malwareType: 'rat' },
    { file: 'stealer.json', malwareType: 'stealer' },
    { file: 'botnet.json', malwareType: 'botnet' },
    { file: 'cryptominers.json', malwareType: 'cryptominer' },
    { file: 'stalkerware.json', malwareType: 'stalkerware' },
] as const;

/** Generic clusters → stored in `galaxy_clusters` table */
const GENERIC_CLUSTERS = [
    { file: 'tool.json', galaxyType: 'tool' },
    { file: 'exploit-kit.json', galaxyType: 'exploit-kit' },
    { file: 'sector.json', galaxyType: 'sector' },
    { file: 'country.json', galaxyType: 'country' },
    { file: 'region.json', galaxyType: 'region' },
    { file: 'microsoft-activity-group.json', galaxyType: 'microsoft-group' },
    { file: 'surveillance-vendor.json', galaxyType: 'surveillance-vendor' },
    { file: 'intelligence-agencies.json', galaxyType: 'intelligence-agency' },
    { file: 'target-information.json', galaxyType: 'target-information' },
    { file: 'branded_vulnerability.json', galaxyType: 'branded-vulnerability' },
    // Tidal Cyber clusters
    { file: 'tidal-campaigns.json', galaxyType: 'tidal-campaign' },
    { file: 'tidal-groups.json', galaxyType: 'tidal-group' },
    { file: 'tidal-software.json', galaxyType: 'tidal-software' },
    { file: 'tidal-technique.json', galaxyType: 'tidal-technique' },
    { file: 'tidal-references.json', galaxyType: 'tidal-reference' },
] as const;

/** Sigma detection rules → stored in `detection_rules` table */
const SIGMA_CLUSTERS = [
    { file: 'sigma-rules.json', ruleType: 'sigma' },
] as const;

// =============================================================================
// Helpers
// =============================================================================

function normalizeName(name: string): string {
    return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function extractSynonyms(meta?: Record<string, unknown>): string[] {
    if (!meta) return [];
    const syns: string[] = [];
    if (Array.isArray(meta.synonyms)) syns.push(...meta.synonyms.map(String));
    if (Array.isArray(meta['alternate-names'])) syns.push(...(meta['alternate-names'] as string[]));
    return syns;
}

function extractRefs(meta?: Record<string, unknown>): string[] {
    if (!meta) return [];
    if (Array.isArray(meta.refs)) return meta.refs.map(String);
    return [];
}

async function fetchCluster(file: string): Promise<MISPCluster> {
    const url = `${BASE}/${file}`;
    log.info(`Fetching ${url}`);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to fetch ${file}: ${resp.status}`);
    return resp.json() as Promise<MISPCluster>;
}

// =============================================================================
// Threat Actor Enrichment Inference (kept from original)
// =============================================================================

const MOTIVATION_KEYWORDS: Record<string, string[]> = {
    'espionage': ['espionage', 'intelligence', 'spy', 'surveillance', 'state-sponsored', 'government-backed', 'cyber espionage'],
    'financial-gain': ['financial', 'ransomware', 'cryptocurrency', 'bitcoin', 'banking', 'fraud', 'theft', 'crimeware', 'money'],
    'disruption': ['destructive', 'wiper', 'sabotage', 'disruption', 'hacktivist'],
    'ideology': ['hacktivist', 'activist', 'political', 'ideological', 'propaganda'],
    'notoriety': ['notorious', 'fame', 'attention', 'publicity'],
    'dominance': ['military', 'warfare', 'dominance', 'strategic'],
};

const SOPHISTICATION_KEYWORDS: Record<string, string[]> = {
    'strategic': ['nation-state', 'state-sponsored', 'advanced persistent threat', 'apt', 'military', 'intelligence agency'],
    'expert': ['sophisticated', 'zero-day', '0-day', 'advanced', 'highly skilled'],
    'advanced': ['professional', 'well-resourced', 'organized', 'persistent'],
    'intermediate': ['moderate', 'capable', 'experienced'],
    'minimal': ['script kiddie', 'amateur', 'basic'],
};

const RESOURCE_LEVEL_KEYWORDS: Record<string, string[]> = {
    'government': ['state-sponsored', 'nation-state', 'government', 'military', 'intelligence', 'pla', 'fsb', 'gru', 'mss'],
    'organization': ['organized crime', 'criminal organization', 'syndicate', 'cartel'],
    'team': ['team', 'group', 'crew', 'gang'],
    'individual': ['lone wolf', 'individual', 'solo'],
};

function toStringValue(val: string | string[] | unknown): string {
    if (!val) return '';
    return (Array.isArray(val) ? val.join(' ') : String(val)).toLowerCase();
}

function inferMotivation(description: string | undefined, meta?: Record<string, unknown>): string | null {
    if (meta?.['cfr-type-of-incident']) {
        const incident = toStringValue(meta['cfr-type-of-incident']);
        if (incident.includes('espionage')) return 'espionage';
        if (incident.includes('financial') || incident.includes('crime')) return 'financial-gain';
        if (incident.includes('sabotage') || incident.includes('destruct')) return 'disruption';
    }
    if (meta?.motive) {
        const motive = toStringValue(meta.motive);
        for (const [motivation, keywords] of Object.entries(MOTIVATION_KEYWORDS)) {
            if (keywords.some(k => motive.includes(k))) return motivation;
        }
    }
    if (!description) return null;
    const descLower = description.toLowerCase();
    for (const [motivation, keywords] of Object.entries(MOTIVATION_KEYWORDS)) {
        if (keywords.some(k => descLower.includes(k))) return motivation;
    }
    return null;
}

function inferSophistication(description: string | undefined, meta?: Record<string, unknown>): string | null {
    if (meta?.['cfr-suspected-state-sponsor'] || meta?.country) return 'strategic';
    if (!description) return null;
    const descLower = description.toLowerCase();
    for (const [level, keywords] of Object.entries(SOPHISTICATION_KEYWORDS)) {
        if (keywords.some(k => descLower.includes(k))) return level;
    }
    return null;
}

function inferResourceLevel(description: string | undefined, meta?: Record<string, unknown>): string | null {
    if (meta?.['cfr-suspected-state-sponsor'] || meta?.country) return 'government';
    if (!description) return null;
    const descLower = description.toLowerCase();
    for (const [level, keywords] of Object.entries(RESOURCE_LEVEL_KEYWORDS)) {
        if (keywords.some(k => descLower.includes(k))) return level;
    }
    return 'organization';
}

// =============================================================================
// Sync: Threat Actors (enrichment of existing + insert new)
// =============================================================================

async function syncThreatActors(): Promise<{ mispActors: number; matched: number; enriched: number; newActors: number }> {
    const galaxy = await fetchCluster('threat-actor.json');
    const stats = { mispActors: galaxy.values.length, matched: 0, enriched: 0, newActors: 0 };

    // Build lookup map by normalized name and aliases
    const mispMap = new Map<string, MISPClusterValue>();
    for (const actor of galaxy.values) {
        mispMap.set(normalizeName(actor.value), actor);
        const syns = extractSynonyms(actor.meta);
        for (const syn of syns) mispMap.set(normalizeName(syn), actor);
    }

    const actors = await db.select().from(threatActors);

    // Enrich existing actors
    for (const actor of actors) {
        const normalizedName = normalizeName(actor.name);
        let mispActor = mispMap.get(normalizedName);
        if (!mispActor && actor.aliases && Array.isArray(actor.aliases)) {
            for (const alias of actor.aliases) {
                if (typeof alias === 'string') {
                    const found = mispMap.get(normalizeName(alias));
                    if (found) { mispActor = found; break; }
                }
            }
        }
        if (!mispActor) continue;
        stats.matched++;

        const motivation = inferMotivation(mispActor.description, mispActor.meta);
        const sophistication = inferSophistication(mispActor.description, mispActor.meta);
        const resourceLevel = inferResourceLevel(mispActor.description, mispActor.meta);

        let goals: string[] = (actor.goals as string[]) || [];
        const meta = mispActor.meta || {};
        if (Array.isArray(meta['targeted-sector'])) goals = [...new Set([...goals, ...(meta['targeted-sector'] as string[])])];
        if (Array.isArray(meta['cfr-target-category'])) goals = [...new Set([...goals, ...(meta['cfr-target-category'] as string[])])];

        const hasNewData = (
            (motivation && actor.primaryMotivation !== motivation) ||
            (sophistication && actor.sophistication !== sophistication) ||
            (resourceLevel && actor.resourceLevel !== resourceLevel) ||
            goals.length > (actor.goals?.length || 0)
        );

        if (hasNewData) {
            await db.update(threatActors)
                .set({
                    primaryMotivation: motivation || actor.primaryMotivation,
                    sophistication: sophistication || actor.sophistication,
                    resourceLevel: resourceLevel || actor.resourceLevel,
                    goals: goals.length > 0 ? goals : actor.goals,
                    updatedAt: new Date(),
                })
                .where(eq(threatActors.id, actor.id));
            stats.enriched++;
        }
    }

    // Insert new actors
    const seen = new Set<string>();
    for (const [name, mispActor] of mispMap) {
        if (seen.has(mispActor.uuid)) continue;
        const exists = actors.some(a =>
            normalizeName(a.name) === name ||
            (a.aliases && (a.aliases as string[]).some(alias => normalizeName(alias) === name))
        );
        if (!exists) {
            seen.add(mispActor.uuid);
            const meta = mispActor.meta || {};
            const goals: string[] = [];
            if (Array.isArray(meta['targeted-sector'])) goals.push(...(meta['targeted-sector'] as string[]));
            if (Array.isArray(meta['cfr-target-category'])) goals.push(...(meta['cfr-target-category'] as string[]));

            await db.insert(threatActors).values({
                stixId: `misp-galaxy--${mispActor.uuid}`,
                name: mispActor.value,
                description: mispActor.description || null,
                aliases: extractSynonyms(mispActor.meta),
                primaryMotivation: inferMotivation(mispActor.description, mispActor.meta),
                sophistication: inferSophistication(mispActor.description, mispActor.meta),
                resourceLevel: inferResourceLevel(mispActor.description, mispActor.meta),
                goals: goals.length > 0 ? [...new Set(goals)] : [],
                country: meta['cfr-suspected-state-sponsor'] as string || null,
            }).onConflictDoNothing();
            stats.newActors++;
        }
    }

    return stats;
}

// =============================================================================
// Sync: Malware Clusters → malware table
// =============================================================================

async function syncMalwareClusters(): Promise<{ total: number; inserted: number; updated: number }> {
    const stats = { total: 0, inserted: 0, updated: 0 };

    for (const { file, malwareType } of MALWARE_CLUSTERS) {
        try {
            const galaxy = await fetchCluster(file);
            log.info(`Syncing malware cluster: ${file}`, { values: galaxy.values.length });

            for (const entry of galaxy.values) {
                stats.total++;
                const stixId = `misp-galaxy--${entry.uuid}`;
                const refs = extractRefs(entry.meta);

                const existing = await db.select({ id: malware.id })
                    .from(malware)
                    .where(eq(malware.stixId, stixId))
                    .limit(1);

                if (existing.length > 0) {
                    // Update description if it was empty
                    await db.update(malware)
                        .set({
                            description: entry.description || undefined,
                            aliases: extractSynonyms(entry.meta),
                            malwareTypes: [malwareType],
                            externalReferences: refs.map(r => ({ url: r })),
                            syncedAt: new Date(),
                            updatedAt: new Date(),
                        })
                        .where(eq(malware.stixId, stixId));
                    stats.updated++;
                } else {
                    await db.insert(malware).values({
                        stixId,
                        name: entry.value,
                        description: entry.description || null,
                        malwareTypes: [malwareType],
                        isFamily: 'true',
                        aliases: extractSynonyms(entry.meta),
                        capabilities: [],
                        labels: [malwareType, 'misp-galaxy'],
                        externalReferences: refs.map(r => ({ url: r })),
                        syncedAt: new Date(),
                    }).onConflictDoNothing();
                    stats.inserted++;
                }
            }
        } catch (err) {
            log.warn(`Failed to sync malware cluster ${file}`, { error: (err as Error).message });
        }
    }

    return stats;
}

// =============================================================================
// Sync: Generic Clusters → galaxy_clusters table
// =============================================================================

async function syncGenericClusters(): Promise<{ total: number; inserted: number; updated: number }> {
    const stats = { total: 0, inserted: 0, updated: 0 };

    for (const { file, galaxyType } of GENERIC_CLUSTERS) {
        try {
            const galaxy = await fetchCluster(file);
            log.info(`Syncing generic cluster: ${file}`, { values: galaxy.values.length });

            for (const entry of galaxy.values) {
                stats.total++;

                const existing = await db.select({ id: galaxyClusters.id })
                    .from(galaxyClusters)
                    .where(eq(galaxyClusters.uuid, entry.uuid))
                    .limit(1);

                if (existing.length > 0) {
                    await db.update(galaxyClusters)
                        .set({
                            name: entry.value,
                            description: entry.description || undefined,
                            aliases: extractSynonyms(entry.meta),
                            meta: (entry.meta || {}) as Record<string, unknown>,
                            externalReferences: extractRefs(entry.meta),
                            syncedAt: new Date(),
                            updatedAt: new Date(),
                        })
                        .where(eq(galaxyClusters.uuid, entry.uuid));
                    stats.updated++;
                } else {
                    await db.insert(galaxyClusters).values({
                        galaxyType,
                        uuid: entry.uuid,
                        name: entry.value,
                        description: entry.description || null,
                        aliases: extractSynonyms(entry.meta),
                        meta: (entry.meta || {}) as Record<string, unknown>,
                        labels: [galaxyType, 'misp-galaxy'],
                        externalReferences: extractRefs(entry.meta),
                        syncedAt: new Date(),
                    }).onConflictDoNothing();
                    stats.inserted++;
                }
            }
        } catch (err) {
            log.warn(`Failed to sync generic cluster ${file}`, { error: (err as Error).message });
        }
    }

    return stats;
}

// =============================================================================
// Sync: Sigma Rules → detection_rules table
// =============================================================================

async function syncSigmaRules(): Promise<{ total: number; inserted: number; updated: number }> {
    const stats = { total: 0, inserted: 0, updated: 0 };

    for (const { file, ruleType } of SIGMA_CLUSTERS) {
        try {
            const galaxy = await fetchCluster(file);
            log.info(`Syncing sigma cluster: ${file}`, { values: galaxy.values.length });

            for (const entry of galaxy.values) {
                stats.total++;
                const meta = (entry.meta || {}) as Record<string, unknown>;

                // Extract severity from meta or infer from tags
                let severity: string | null = null;
                if (typeof meta.level === 'string') {
                    severity = meta.level;
                }

                // Extract status
                let status: string | null = null;
                if (typeof meta.status === 'string') {
                    status = meta.status;
                }

                // Extract tags (MITRE ATT&CK etc.)
                const tags: string[] = Array.isArray(meta.tags) ? meta.tags.map(String) : [];

                const existing = await db.select({ id: detectionRules.id })
                    .from(detectionRules)
                    .where(eq(detectionRules.uuid, entry.uuid))
                    .limit(1);

                if (existing.length > 0) {
                    await db.update(detectionRules)
                        .set({
                            name: entry.value,
                            description: entry.description || undefined,
                            severity,
                            status,
                            tags,
                            meta: meta,
                            externalReferences: extractRefs(entry.meta),
                            syncedAt: new Date(),
                            updatedAt: new Date(),
                        })
                        .where(eq(detectionRules.uuid, entry.uuid));
                    stats.updated++;
                } else {
                    await db.insert(detectionRules).values({
                        ruleType,
                        uuid: entry.uuid,
                        name: entry.value,
                        description: entry.description || null,
                        severity,
                        status,
                        tags,
                        meta: meta,
                        externalReferences: extractRefs(entry.meta),
                        syncedAt: new Date(),
                    }).onConflictDoNothing();
                    stats.inserted++;
                }
            }
        } catch (err) {
            log.warn(`Failed to sync sigma cluster ${file}`, { error: (err as Error).message });
        }
    }

    return stats;
}

// =============================================================================
// Main Entry Points
// =============================================================================

export interface GalaxySyncResult {
    threatActors: { mispActors: number; matched: number; enriched: number; newActors: number };
    malware: { total: number; inserted: number; updated: number };
    generic: { total: number; inserted: number; updated: number };
    sigma: { total: number; inserted: number; updated: number };
    durationMs: number;
}

/** Full sync — all cluster types */
export async function syncMISPGalaxy(): Promise<GalaxySyncResult> {
    const start = Date.now();
    log.info('Starting full MISP Galaxy sync');

    const [actorStats, malwareStats, genericStats, sigmaStats] = await Promise.all([
        syncThreatActors(),
        syncMalwareClusters(),
        syncGenericClusters(),
        syncSigmaRules(),
    ]);

    const result: GalaxySyncResult = {
        threatActors: actorStats,
        malware: malwareStats,
        generic: genericStats,
        sigma: sigmaStats,
        durationMs: Date.now() - start,
    };

    log.info('Full MISP Galaxy sync complete', result as unknown as Record<string, unknown>);
    return result;
}

/** Backward-compatible alias used by scheduler and additionalFeeds */
export async function runMISPGalaxySync(): Promise<void> {
    const startedAt = new Date();
    log.info('Starting full sync');

    try {
        const { workerTelemetry } = await import('../lib/telemetry');
        const endSync = workerTelemetry.startSync('misp-galaxy');
        const stats = await syncMISPGalaxy();

        const totalItems = stats.threatActors.enriched + stats.malware.inserted + stats.generic.inserted + stats.sigma.inserted;

        // Record per-category metrics
        workerTelemetry.recordSync('misp-galaxy-actors', stats.threatActors.newActors + stats.threatActors.enriched, stats.durationMs, true);
        workerTelemetry.recordSync('misp-galaxy-malware', stats.malware.inserted + stats.malware.updated, stats.durationMs, true);
        workerTelemetry.recordSync('misp-galaxy-generic', stats.generic.inserted + stats.generic.updated, stats.durationMs, true);
        workerTelemetry.recordSync('misp-galaxy-sigma', stats.sigma.inserted + stats.sigma.updated, stats.durationMs, true);

        endSync({ items: totalItems, success: true });

        await db.insert(syncLogs).values({
            entityType: 'misp_galaxy',
            status: 'success',
            itemsProcessed: totalItems,
            itemsFailed: 0,
            errorMessage: null,
            startedAt,
            completedAt: new Date(),
        });

        log.info('Full sync completed', stats as unknown as Record<string, unknown>);
    } catch (error) {
        log.error('Sync failed', error);

        try {
            const { workerTelemetry } = await import('../lib/telemetry');
            workerTelemetry.recordSync('misp-galaxy', 0, Date.now() - startedAt.getTime(), false);
        } catch { /* telemetry best-effort */ }

        await db.insert(syncLogs).values({
            entityType: 'misp_galaxy',
            status: 'error',
            itemsProcessed: 0,
            itemsFailed: 1,
            errorMessage: (error as Error).message,
            startedAt,
            completedAt: new Date(),
        });

        throw error;
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runMISPGalaxySync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
