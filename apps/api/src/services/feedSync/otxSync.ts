/**
 * OTX Feed Sync
 */

import { notifyNewIOC, notifySyncStatus } from '../../websocket';
import { db } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import type { OTXPulse, OTXSyncOptions, SyncResult } from './types';
import { otxFetch, mapOTXType, getExistingIOCValues, getExistingPulseIds } from './otxClient';

const log = createLogger('FeedSync:otx');

export async function fetchSubscribedPulses(options: OTXSyncOptions = {}): Promise<OTXPulse[]> {
    const params = new URLSearchParams();
    if (options.limit) params.set('limit', options.limit.toString());
    if (options.modifiedSince) params.set('modified_since', options.modifiedSince);

    const queryString = params.toString() ? `?${params.toString()}` : '';

    const data = await otxFetch<{ results: OTXPulse[] }>(`/pulses/subscribed${queryString}`);
    return data.results || [];
}

export async function syncOTXFeed(options: OTXSyncOptions = {}): Promise<SyncResult> {
    const result: SyncResult = {
        success: true,
        pulsesProcessed: 0,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors: [],
        pulses: [],
        indicators: [],
    };

    const MAX_INDICATORS_FOR_ENRICHMENT = 50;

    try {
        log.info('Fetching subscribed pulses...');
        const pulses = await fetchSubscribedPulses({ limit: options.limit || 10, ...options });
        log.info('Found pulses', { count: pulses.length });

        // Collect all indicator values for batch delta check
        const allIndicatorValues: string[] = [];
        for (const pulse of pulses) {
            if (pulse.indicators) {
                for (const ind of pulse.indicators) {
                    allIndicatorValues.push(ind.indicator);
                }
            }
        }

        // Batch-check which values already exist in DB
        const existingValues = await getExistingIOCValues(allIndicatorValues);
        log.info('Delta check complete', { totalIndicators: allIndicatorValues.length, existingInDB: existingValues.size });

        // Also check which pulses are new
        const existingPulses = await getExistingPulseIds(pulses.map(p => p.id));

        for (const pulse of pulses) {
            const indicatorCount = pulse.indicators?.length || 0;
            const isNewPulse = !existingPulses.has(pulse.id);

            // Count actual new indicators in this pulse
            let newInThisPulse = 0;
            if (pulse.indicators) {
                for (const ind of pulse.indicators) {
                    if (!existingValues.has(ind.indicator)) {
                        newInThisPulse++;
                    }
                }
            }

            result.pulses!.push({
                id: pulse.id,
                name: pulse.name,
                indicatorCount,
            });
            result.indicatorsProcessed += indicatorCount;
            result.indicatorsAdded += newInThisPulse;
            if (!isNewPulse) {
                result.indicatorsUpdated += (indicatorCount - newInThisPulse);
            }
            result.pulsesProcessed++;

            for (const indicator of pulse.indicators) {
                if (result.indicators!.length >= MAX_INDICATORS_FOR_ENRICHMENT) break;

                // Only include genuinely new indicators for enrichment
                if (existingValues.has(indicator.indicator)) continue;

                const mappedType = mapOTXType(indicator.type);
                // Only include enrichable types (skip unknown)
                if (mappedType !== 'unknown') {
                    result.indicators!.push({
                        id: `otx-${pulse.id}-${indicator.id}`,
                        value: indicator.indicator,
                        type: mappedType,
                    });
                }
            }

            // PERSISTENCE: Insert ALL new indicators into DB
            if (pulse.indicators && pulse.indicators.length > 0) {
                const indicatorsToInsert = [];
                for (const ind of pulse.indicators) {
                    if (!existingValues.has(ind.indicator)) {
                        const mappedType = mapOTXType(ind.type);
                        if (mappedType !== 'unknown') {
                            indicatorsToInsert.push({
                                type: mappedType,
                                value: ind.indicator,
                                source: 'otx',
                                pulseId: pulse.id,
                                description: ind.description || pulse.description || null,
                                firstSeen: ind.created ? new Date(ind.created) : new Date(),
                                lastSeen: new Date(),
                                tags: pulse.tags || [],
                                created_at: new Date(),
                                updated_at: new Date(),
                            });
                            existingValues.add(ind.indicator);
                        }
                    }
                }

                if (indicatorsToInsert.length > 0) {
                    try {
                        const BATCH_SIZE = 500;
                        for (let i = 0; i < indicatorsToInsert.length; i += BATCH_SIZE) {
                            const batch = indicatorsToInsert.slice(i, i + BATCH_SIZE);
                            await db.insert(iocs).values(batch).onConflictDoNothing();
                        }
                    } catch (dbErr) {
                        log.error('Failed to insert IOCs', new Error((dbErr as Error).message), { pulseId: pulse.id });
                        result.errors.push(`DB Insert failed for pulse ${pulse.id}: ${(dbErr as Error).message}`);
                    }
                }
            }
        }

        const newPulses = pulses.length - existingPulses.size;
        log.info('Sync complete', { pulsesProcessed: result.pulsesProcessed, newPulses, indicatorsProcessed: result.indicatorsProcessed, indicatorsAdded: result.indicatorsAdded, forEnrichment: result.indicators!.length });

        // Broadcast sync completion to dashboard clients
        notifySyncStatus({
            feed: 'otx',
            status: 'completed',
            processed: result.indicatorsProcessed,
            message: `Synced ${result.pulsesProcessed} pulses — ${result.indicatorsAdded} new indicators (${result.indicatorsProcessed} total processed)`,
        });

        // Broadcast first few new IOCs (up to 5) for live updates
        for (const ioc of result.indicators!.slice(0, 5)) {
            notifyNewIOC({
                type: ioc.type,
                value: ioc.value,
                source: 'otx',
            });
        }

    } catch (err) {
        result.success = false;
        result.errors.push(`Sync failed: ${(err as Error).message}`);
        log.error('Sync error:', (err as Error).message);

        notifySyncStatus({
            feed: 'otx',
            status: 'failed',
            message: (err as Error).message,
        });
    }

    return result;
}
