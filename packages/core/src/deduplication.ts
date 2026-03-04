/**
 * IOC Deduplication Service
 * 
 * Provides canonical ID generation and deduplication logic for IOCs.
 * When the same IOC (type + normalized value) is seen from multiple sources,
 * we merge the intelligence rather than creating duplicates.
 */

import { createHash } from 'crypto';
import { db } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { eq, and } from 'drizzle-orm';

// ============================================================================
// Canonical ID Generation
// ============================================================================

/**
 * Normalize IOC value for consistent matching
 * - IPs: strip leading zeros
 * - Domains: lowercase, remove trailing dots
 * - URLs: lowercase protocol and domain
 * - Hashes: lowercase
 * - Emails: lowercase
 */
export function normalizeIOCValue(type: string, value: string): string {
    const trimmed = value.trim();

    switch (type) {
        case 'ip':
        case 'ipv4':
        case 'ipv6':
            // Normalize IP: remove leading zeros from octets
            return trimmed.split('.').map(octet => {
                const num = parseInt(octet, 10);
                return isNaN(num) ? octet : String(num);
            }).join('.');

        case 'domain':
        case 'hostname':
            // Lowercase and remove trailing dot
            return trimmed.toLowerCase().replace(/\.+$/, '');

        case 'url':
            // Lowercase protocol and domain, preserve path case
            try {
                const url = new URL(trimmed);
                url.hostname = url.hostname.toLowerCase();
                url.protocol = url.protocol.toLowerCase();
                return url.toString();
            } catch {
                return trimmed.toLowerCase();
            }

        case 'hash-md5':
        case 'hash-sha1':
        case 'hash-sha256':
        case 'md5':
        case 'sha1':
        case 'sha256':
            return trimmed.toLowerCase();

        case 'email':
            return trimmed.toLowerCase();

        default:
            return trimmed;
    }
}

/**
 * Generate canonical ID for an IOC
 * Format: sha256(type + ':' + normalizedValue)
 * This creates a consistent, unique identifier regardless of source
 */
export function generateCanonicalId(type: string, value: string): string {
    const normalizedType = type.toLowerCase().replace(/^hash-/, '');
    const normalizedValue = normalizeIOCValue(type, value);
    const input = `${normalizedType}:${normalizedValue}`;

    return createHash('sha256').update(input).digest('hex').substring(0, 32);
}

// ============================================================================
// Deduplication Logic
// ============================================================================

export interface IOCInput {
    type: string;
    value: string;
    source: string;
    threatType?: string | null;
    confidence?: number | null;
    severity?: string | null;
    firstSeen?: Date | null;
    lastSeen?: Date | null;
    tags?: string[] | null;
    pulseId?: string | null;
    rawData?: Record<string, unknown> | null;
}

export interface DeduplicationResult {
    id: string;
    canonicalId: string;
    action: 'created' | 'updated' | 'skipped';
    merged: boolean;
    sources: string[];
}

/**
 * Merge two IOC records, preferring newer/higher confidence data
 */
function mergeIOCData(existing: any, incoming: IOCInput): Partial<IOCInput> {
    const merged: Partial<IOCInput> = {};

    // Merge confidence - take higher
    if (incoming.confidence !== undefined && incoming.confidence !== null) {
        if (!existing.confidence || incoming.confidence > existing.confidence) {
            merged.confidence = incoming.confidence;
        }
    }

    // Merge severity - take more severe
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    if (incoming.severity) {
        const existingIdx = severityOrder.indexOf(existing.severity || '');
        const incomingIdx = severityOrder.indexOf(incoming.severity);
        if (incomingIdx > existingIdx) {
            merged.severity = incoming.severity;
        }
    }

    // Merge threatType - prefer non-null
    if (incoming.threatType && !existing.threatType) {
        merged.threatType = incoming.threatType;
    }

    // Merge firstSeen - take earlier
    if (incoming.firstSeen) {
        if (!existing.firstSeen || incoming.firstSeen < existing.firstSeen) {
            merged.firstSeen = incoming.firstSeen;
        }
    }

    // Merge lastSeen - take later
    if (incoming.lastSeen) {
        if (!existing.lastSeen || incoming.lastSeen > existing.lastSeen) {
            merged.lastSeen = incoming.lastSeen;
        }
    }

    // Merge tags - union
    if (incoming.tags && incoming.tags.length > 0) {
        const existingTags = existing.tags || [];
        const newTags = [...new Set([...existingTags, ...incoming.tags])];
        if (newTags.length > existingTags.length) {
            merged.tags = newTags;
        }
    }

    return merged;
}

/**
 * Upsert an IOC with deduplication
 * If the IOC already exists (same canonical ID), merge the data
 */
export async function upsertIOC(input: IOCInput): Promise<DeduplicationResult> {
    const canonicalId = generateCanonicalId(input.type, input.value);
    const normalizedValue = normalizeIOCValue(input.type, input.value);

    // Check for existing IOC with same value (canonical match)
    const [existing] = await db.select()
        .from(iocs)
        .where(eq(iocs.value, normalizedValue))
        .limit(1);

    if (existing) {
        // Check if source is already recorded
        const existingRawData = existing.rawData as Record<string, unknown> || {};
        const existingSources = (existingRawData.sources as string[]) || [existing.source];

        if (existingSources.includes(input.source)) {
            // Same source, same IOC - skip or update lastSeen
            const updates: any = { updatedAt: new Date() };
            if (input.lastSeen && (!existing.lastSeen || input.lastSeen > existing.lastSeen)) {
                updates.lastSeen = input.lastSeen;
            }

            await db.update(iocs)
                .set(updates)
                .where(eq(iocs.id, existing.id));

            return {
                id: existing.id,
                canonicalId,
                action: 'skipped',
                merged: false,
                sources: existingSources,
            };
        }

        // New source for existing IOC - merge
        const merged = mergeIOCData(existing, input);
        const newSources = [...existingSources, input.source];

        await db.update(iocs)
            .set({
                ...merged,
                rawData: {
                    ...existingRawData,
                    sources: newSources,
                    lastMergedFrom: input.source,
                    lastMergedAt: new Date().toISOString(),
                },
                updatedAt: new Date(),
            })
            .where(eq(iocs.id, existing.id));

        return {
            id: existing.id,
            canonicalId,
            action: 'updated',
            merged: true,
            sources: newSources,
        };
    }

    // New IOC - insert
    const [inserted] = await db.insert(iocs)
        .values({
            type: input.type,
            value: normalizedValue,
            source: input.source,
            threatType: input.threatType,
            confidence: input.confidence,
            severity: input.severity,
            firstSeen: input.firstSeen,
            lastSeen: input.lastSeen,
            tags: input.tags,
            pulseId: input.pulseId,
            rawData: {
                ...input.rawData,
                canonicalId,
                sources: [input.source],
            },
            createdAt: new Date(),
            updatedAt: new Date(),
        })
        .returning({ id: iocs.id });

    return {
        id: inserted.id,
        canonicalId,
        action: 'created',
        merged: false,
        sources: [input.source],
    };
}

/**
 * Batch upsert IOCs with deduplication
 */
export async function batchUpsertIOCs(inputs: IOCInput[]): Promise<{
    created: number;
    updated: number;
    skipped: number;
    results: DeduplicationResult[];
}> {
    const results: DeduplicationResult[] = [];
    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const input of inputs) {
        try {
            const result = await upsertIOC(input);
            results.push(result);

            switch (result.action) {
                case 'created': created++; break;
                case 'updated': updated++; break;
                case 'skipped': skipped++; break;
            }
        } catch (error) {
            console.error(`Failed to upsert IOC ${input.type}:${input.value}:`, error);
        }
    }

    return { created, updated, skipped, results };
}

// ============================================================================
// Deduplication Stats
// ============================================================================

export async function getDeduplicationStats(): Promise<{
    totalIOCs: number;
    uniqueValues: number;
    multiSourceIOCs: number;
    bySource: Record<string, number>;
}> {
    // Get count of IOCs with multiple sources
    const allIOCs = await db.select({
        id: iocs.id,
        source: iocs.source,
        rawData: iocs.rawData,
    }).from(iocs);

    const bySource: Record<string, number> = {};
    let multiSourceCount = 0;

    for (const ioc of allIOCs) {
        bySource[ioc.source] = (bySource[ioc.source] || 0) + 1;

        const rawData = ioc.rawData as Record<string, unknown> || {};
        const sources = rawData.sources as string[];
        if (sources && sources.length > 1) {
            multiSourceCount++;
        }
    }

    return {
        totalIOCs: allIOCs.length,
        uniqueValues: allIOCs.length, // Already deduplicated
        multiSourceIOCs: multiSourceCount,
        bySource,
    };
}
