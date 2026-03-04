/**
 * Rinjani Sync Worker
 * 
 * Syncs data from external GraphQL API to the v3 PostgreSQL database.
 * Runs as a background process to keep data in sync.
 */

import { db } from '@rinjani/db';
import { threatActors, indicators, malware, syncLogs } from '@rinjani/db/schema';
import { eq } from '@rinjani/db';

// ============================================================================
// Configuration
// ============================================================================

const EXTERNAL_API_URL = process.env.EXTERNAL_API_URL || 'http://localhost:4000';
const EXTERNAL_API_TOKEN = process.env.EXTERNAL_API_TOKEN || '';
const SYNC_INTERVAL = parseInt(process.env.SYNC_INTERVAL || '300000', 10); // 5 minutes

// ============================================================================
// GraphQL Queries
// ============================================================================

const THREAT_ACTORS_QUERY = `
query ThreatActors($first: Int, $after: ID) {
    threatActors(first: $first, after: $after) {
        edges {
            node {
                id
                standard_id
                name
                description
                aliases
                sophistication
                resource_level
                primary_motivation
                secondary_motivations
                goals
                created
                modified
            }
        }
        pageInfo {
            hasNextPage
            endCursor
        }
    }
}
`;

const INDICATORS_QUERY = `
query Indicators($first: Int, $after: ID) {
    indicators(first: $first, after: $after) {
        edges {
            node {
                id
                standard_id
                pattern
                pattern_type
                pattern_version
                name
                description
                valid_from
                valid_until
                created
                modified
            }
        }
        pageInfo {
            hasNextPage
            endCursor
        }
    }
}
`;

// ============================================================================
// GraphQL Client
// ============================================================================

async function graphqlRequest<T>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
    const response = await fetch(`${EXTERNAL_API_URL}/graphql`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${EXTERNAL_API_TOKEN}`,
        },
        body: JSON.stringify({ query, variables }),
    });

    if (!response.ok) {
        throw new Error(`GraphQL request failed: ${response.status}`);
    }

    const result = await response.json() as { errors?: unknown[]; data: T };

    if (result.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(result.errors)}`);
    }

    return result.data;
}

// ============================================================================
// Sync Functions
// ============================================================================

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

async function syncThreatActors(): Promise<SyncResult> {
    console.log('[Sync] Starting threat actors sync...');
    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    let hasNextPage = true;
    let cursor: string | null = null;

    while (hasNextPage) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const data: any = await graphqlRequest(THREAT_ACTORS_QUERY, {
                first: 100,
                after: cursor,
            });

            const edges = data.threatActors?.edges || [];

            for (const edge of edges) {
                const node = edge.node;
                try {
                    // Upsert threat actor
                    const existing = await db.select()
                        .from(threatActors)
                        .where(eq(threatActors.stixId, node.standard_id))
                        .limit(1);

                    const actorData = {
                        stixId: node.standard_id,
                        name: node.name,
                        description: node.description || null,
                        aliases: node.aliases || [],
                        sophistication: node.sophistication || null,
                        resourceLevel: node.resource_level || null,
                        primaryMotivation: node.primary_motivation || null,
                        secondaryMotivations: node.secondary_motivations || [],
                        goals: node.goals || [],
                        labels: [], // Labels may not be available from external API
                        stixCreated: node.created ? new Date(node.created) : null,
                        stixModified: node.modified ? new Date(node.modified) : null,
                        syncedAt: new Date(),
                    };

                    if (existing.length > 0) {
                        await db.update(threatActors)
                            .set({ ...actorData, updatedAt: new Date() })
                            .where(eq(threatActors.stixId, node.standard_id));
                    } else {
                        await db.insert(threatActors).values(actorData);
                    }

                    result.processed++;
                } catch (error) {
                    result.failed++;
                    result.errors.push(`Threat actor ${node.name}: ${error}`);
                }
            }

            hasNextPage = data.threatActors?.pageInfo?.hasNextPage || false;
            cursor = data.threatActors?.pageInfo?.endCursor || null;
        } catch (error) {
            console.error('[Sync] Error fetching threat actors:', error);
            hasNextPage = false;
            result.errors.push(`Fetch error: ${error}`);
        }
    }

    console.log(`[Sync] Threat actors: ${result.processed} processed, ${result.failed} failed`);
    return result;
}

async function syncIndicators(): Promise<SyncResult> {
    console.log('[Sync] Starting indicators sync...');
    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    let hasNextPage = true;
    let cursor: string | null = null;

    while (hasNextPage) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const data: any = await graphqlRequest(INDICATORS_QUERY, {
                first: 100,
                after: cursor,
            });

            const edges = data.indicators?.edges || [];

            for (const edge of edges) {
                const node = edge.node;
                try {
                    const existing = await db.select()
                        .from(indicators)
                        .where(eq(indicators.stixId, node.standard_id))
                        .limit(1);

                    const indicatorData = {
                        stixId: node.standard_id,
                        pattern: node.pattern,
                        patternType: node.pattern_type,
                        patternVersion: node.pattern_version || null,
                        name: node.name || null,
                        description: node.description || null,
                        validFrom: node.valid_from ? new Date(node.valid_from) : null,
                        validUntil: node.valid_until ? new Date(node.valid_until) : null,
                        labels: [], // Labels may not be available from external API
                        stixCreated: node.created ? new Date(node.created) : null,
                        stixModified: node.modified ? new Date(node.modified) : null,
                        syncedAt: new Date(),
                    };

                    if (existing.length > 0) {
                        await db.update(indicators)
                            .set({ ...indicatorData, updatedAt: new Date() })
                            .where(eq(indicators.stixId, node.standard_id));
                    } else {
                        await db.insert(indicators).values(indicatorData);
                    }

                    result.processed++;
                } catch (error) {
                    result.failed++;
                    result.errors.push(`Indicator ${node.name}: ${error}`);
                }
            }

            hasNextPage = data.indicators?.pageInfo?.hasNextPage || false;
            cursor = data.indicators?.pageInfo?.endCursor || null;
        } catch (error) {
            console.error('[Sync] Error fetching indicators:', error);
            hasNextPage = false;
            result.errors.push(`Fetch error: ${error}`);
        }
    }

    console.log(`[Sync] Indicators: ${result.processed} processed, ${result.failed} failed`);
    return result;
}

// ============================================================================
// Sync Log
// ============================================================================

async function logSync(
    entityType: string,
    result: SyncResult,
    startedAt: Date
): Promise<void> {
    await db.insert(syncLogs).values({
        entityType,
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// ============================================================================
// Main Sync Runner
// ============================================================================

export async function runFullSync(): Promise<void> {
    console.log('[Sync] Starting full sync...');
    console.log(`[Sync] External API URL: ${EXTERNAL_API_URL}`);

    const startedAt = new Date();

    try {
        // Sync threat actors
        const threatResult = await syncThreatActors();
        await logSync('threat_actors', threatResult, startedAt);

        // Sync indicators
        const indicatorResult = await syncIndicators();
        await logSync('indicators', indicatorResult, startedAt);

        console.log('[Sync] Full sync completed!');
        console.log(`[Sync] Threat actors: ${threatResult.processed} synced`);
        console.log(`[Sync] Indicators: ${indicatorResult.processed} synced`);
    } catch (error) {
        console.error('[Sync] Full sync failed:', error);
        await logSync('full_sync', { processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// ============================================================================
// Run Continuous Sync (optional daemon mode)
// ============================================================================

export async function startSyncDaemon(): Promise<void> {
    console.log(`[Sync] Starting sync daemon (interval: ${SYNC_INTERVAL}ms)...`);

    // Initial sync
    await runFullSync();

    // Periodic sync
    setInterval(async () => {
        await runFullSync();
    }, SYNC_INTERVAL);
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runFullSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
