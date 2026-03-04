/**
 * MISP Galaxy Threat Actor Enrichment Feed
 * 
 * Fetches threat actor metadata from MISP Galaxy (no API key required).
 * Enriches existing threat actors with motivation, sophistication, 
 * resource level, and country information.
 * 
 * Source: https://github.com/MISP/misp-galaxy (Public GitHub repository)
 */

import { db } from '@rinjani/db';
import { threatActors, syncLogs } from '@rinjani/db/schema';
import { eq } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('MISPGalaxy');

// MISP Galaxy Threat Actor Cluster URL
const MISP_GALAXY_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json';

// =============================================================================
// Types
// =============================================================================

interface MISPActor {
    value: string;
    description?: string;
    uuid: string;
    meta?: {
        'cfr-type-of-incident'?: string | string[];
        'cfr-suspected-state-sponsor'?: string;
        'cfr-target-category'?: string[];
        'cfr-suspected-victims'?: string[];
        'targeted-sector'?: string[];
        country?: string;
        synonyms?: string[];
        refs?: string[];
        'attribution-confidence'?: string;
        motive?: string | string[];
    };
}

interface MISPGalaxy {
    name: string;
    type: string;
    description: string;
    values: MISPActor[];
}

// =============================================================================
// Motivation Keywords for Inference
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

// =============================================================================
// Inference Functions
// =============================================================================

function toStringValue(val: string | string[] | undefined): string {
    if (!val) return '';
    return (Array.isArray(val) ? val.join(' ') : String(val)).toLowerCase();
}

function inferMotivation(description: string | undefined, mispMeta?: MISPActor['meta']): string | null {
    // First check MISP cfr-type-of-incident
    if (mispMeta?.['cfr-type-of-incident']) {
        const incident = toStringValue(mispMeta['cfr-type-of-incident']);
        if (incident.includes('espionage')) return 'espionage';
        if (incident.includes('financial') || incident.includes('crime')) return 'financial-gain';
        if (incident.includes('sabotage') || incident.includes('destruct')) return 'disruption';
    }

    // Check explicit motive field
    if (mispMeta?.motive) {
        const motive = toStringValue(mispMeta.motive);
        for (const [motivation, keywords] of Object.entries(MOTIVATION_KEYWORDS)) {
            if (keywords.some(k => motive.includes(k))) return motivation;
        }
    }

    // Fall back to description keyword analysis
    if (!description) return null;
    const descLower = description.toLowerCase();

    for (const [motivation, keywords] of Object.entries(MOTIVATION_KEYWORDS)) {
        if (keywords.some(k => descLower.includes(k))) return motivation;
    }
    return null;
}

function inferSophistication(description: string | undefined, mispMeta?: MISPActor['meta']): string | null {
    // State-sponsored = strategic level
    if (mispMeta?.['cfr-suspected-state-sponsor'] || mispMeta?.country) {
        return 'strategic';
    }

    if (!description) return null;
    const descLower = description.toLowerCase();

    for (const [level, keywords] of Object.entries(SOPHISTICATION_KEYWORDS)) {
        if (keywords.some(k => descLower.includes(k))) return level;
    }
    return null;
}

function inferResourceLevel(description: string | undefined, mispMeta?: MISPActor['meta']): string | null {
    // State-sponsored = government level
    if (mispMeta?.['cfr-suspected-state-sponsor'] || mispMeta?.country) {
        return 'government';
    }

    if (!description) return null;
    const descLower = description.toLowerCase();

    for (const [level, keywords] of Object.entries(RESOURCE_LEVEL_KEYWORDS)) {
        if (keywords.some(k => descLower.includes(k))) return level;
    }
    return 'organization';
}

function normalizeName(name: string): string {
    return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

// =============================================================================
// Main Sync Function
// =============================================================================

export async function syncMISPGalaxy(): Promise<{
    mispActors: number;
    matched: number;
    enriched: number;
    newActors: number;
}> {
    log.info('Fetching threat actor data');

    const response = await fetch(MISP_GALAXY_URL);
    if (!response.ok) {
        throw new Error(`Failed to fetch MISP Galaxy: ${response.status}`);
    }

    const galaxy = await response.json() as MISPGalaxy;
    log.info('Received threat actors', { count: galaxy.values.length });

    const stats = {
        mispActors: galaxy.values.length,
        matched: 0,
        enriched: 0,
        newActors: 0,
    };

    // Build lookup map by normalized name and aliases
    const mispMap = new Map<string, MISPActor>();
    for (const actor of galaxy.values) {
        mispMap.set(normalizeName(actor.value), actor);
        if (actor.meta?.synonyms) {
            for (const syn of actor.meta.synonyms) {
                mispMap.set(normalizeName(syn), actor);
            }
        }
    }
    log.info('Built lookup index', { entries: mispMap.size });

    // Get all existing threat actors from our database
    const actors = await db.select().from(threatActors);
    log.info('Found actors in database', { count: actors.length });

    // Enrich existing actors
    for (const actor of actors) {
        const normalizedName = normalizeName(actor.name);
        let mispActor = mispMap.get(normalizedName);

        // Also check aliases from our DB
        if (!mispActor && actor.aliases && Array.isArray(actor.aliases)) {
            for (const alias of actor.aliases) {
                if (typeof alias === 'string') {
                    const found = mispMap.get(normalizeName(alias));
                    if (found) {
                        mispActor = found;
                        break;
                    }
                }
            }
        }

        if (!mispActor) continue;
        stats.matched++;

        // Infer enrichment data
        const motivation = inferMotivation(mispActor.description, mispActor.meta);
        const sophistication = inferSophistication(mispActor.description, mispActor.meta);
        const resourceLevel = inferResourceLevel(mispActor.description, mispActor.meta);

        // Build goals from target sectors
        let goals: string[] = (actor.goals as string[]) || [];
        if (mispActor.meta?.['targeted-sector']) {
            goals = [...new Set([...goals, ...mispActor.meta['targeted-sector']])];
        }
        if (mispActor.meta?.['cfr-target-category']) {
            goals = [...new Set([...goals, ...mispActor.meta['cfr-target-category']])];
        }

        // Check if we have new data to update
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

    // Also add actors from MISP Galaxy that don't exist in our DB
    const seen = new Set<string>(); // Track by UUID to avoid synonym duplicates
    for (const [name, mispActor] of mispMap) {
        if (seen.has(mispActor.uuid)) continue;

        const exists = actors.some(a =>
            normalizeName(a.name) === name ||
            (a.aliases && (a.aliases as string[]).some(alias => normalizeName(alias) === name))
        );

        if (!exists) {
            seen.add(mispActor.uuid);

            // Build goals from target sectors
            const goals: string[] = [];
            if (mispActor.meta?.['targeted-sector']) goals.push(...mispActor.meta['targeted-sector']);
            if (mispActor.meta?.['cfr-target-category']) goals.push(...mispActor.meta['cfr-target-category']);

            await db.insert(threatActors).values({
                stixId: `misp-galaxy--${mispActor.uuid}`,
                name: mispActor.value,
                description: mispActor.description || null,
                aliases: mispActor.meta?.synonyms || [],
                primaryMotivation: inferMotivation(mispActor.description, mispActor.meta),
                sophistication: inferSophistication(mispActor.description, mispActor.meta),
                resourceLevel: inferResourceLevel(mispActor.description, mispActor.meta),
                goals: goals.length > 0 ? [...new Set(goals)] : [],
            }).onConflictDoNothing();
            stats.newActors++;
        }
    }

    log.info('Sync complete', stats);
    return stats;
}

// Export alias for consistency with other feeds
export async function runMISPGalaxySync(): Promise<void> {
    const startedAt = new Date();
    log.info('Starting full sync');

    try {
        const stats = await syncMISPGalaxy();

        // Log sync results to database for monitoring
        await db.insert(syncLogs).values({
            entityType: 'misp_galaxy',
            status: 'success',
            itemsProcessed: stats.enriched,
            itemsFailed: 0,
            errorMessage: null,
            startedAt,
            completedAt: new Date(),
        });

        log.info('Full sync completed');
    } catch (error) {
        log.error('Sync failed', error);

        // Log error to database
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

