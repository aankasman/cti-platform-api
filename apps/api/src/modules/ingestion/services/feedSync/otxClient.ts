/**
 * OTX API Client & Helpers
 */

import { db, sql } from '@rinjani/db';
import { iocs, pulses as pulsesTable } from '@rinjani/db/schema';
import { createLogger } from '../../../../lib/logger';

const log = createLogger('FeedSync:otxClient');

// =============================================================================
// OTX API Client
// =============================================================================

const OTX_BASE_URL = process.env.ALIENVAULT_BASE_URL || 'https://otx.alienvault.com';
const OTX_API_KEY = process.env.ALIENVAULT_API_KEY;

export async function otxFetch<T>(endpoint: string): Promise<T> {
    if (!OTX_API_KEY) {
        throw new Error('ALIENVAULT_API_KEY not configured');
    }

    const response = await fetch(`${OTX_BASE_URL}/api/v1${endpoint}`, {
        headers: {
            'X-OTX-API-KEY': OTX_API_KEY,
            'Accept': 'application/json',
        },
    });

    if (!response.ok) {
        throw new Error(`OTX API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
}

// =============================================================================
// IOC Type Mapping
// =============================================================================

const OTX_TYPE_MAP: Record<string, string> = {
    'IPv4': 'ip',
    'IPv6': 'ip',
    'domain': 'domain',
    'hostname': 'domain',
    'URL': 'url',
    'URI': 'url',
    'FileHash-MD5': 'hash',
    'FileHash-SHA1': 'hash',
    'FileHash-SHA256': 'hash',
    'email': 'email',
    'CVE': 'cve',
};

export function mapOTXType(otxType: string): string {
    return OTX_TYPE_MAP[otxType] || 'unknown';
}

// =============================================================================
// Delta Checking Helpers
// =============================================================================

/**
 * Batch-check which IOC values already exist in PostgreSQL.
 * Returns a Set of existing values for O(1) lookup.
 */
export async function getExistingIOCValues(values: string[]): Promise<Set<string>> {
    if (values.length === 0) return new Set();

    const existing = new Set<string>();

    // Process in batches of 500 to avoid query limit
    const BATCH_SIZE = 500;
    for (let i = 0; i < values.length; i += BATCH_SIZE) {
        const batch = values.slice(i, i + BATCH_SIZE);
        try {
            const rows = await db.select({ value: iocs.value })
                .from(iocs)
                .where(sql`${iocs.value} IN ${batch}`);
            for (const row of rows) {
                existing.add(row.value);
            }
        } catch (err) {
            log.warn('Delta check batch failed', { error: (err as Error).message });
        }
    }

    return existing;
}

/**
 * Check which pulse IDs already exist in our pulses table.
 */
export async function getExistingPulseIds(otxIds: string[]): Promise<Set<string>> {
    if (otxIds.length === 0) return new Set();

    const existing = new Set<string>();
    try {
        const rows = await db.select({ otxId: pulsesTable.otxId })
            .from(pulsesTable)
            .where(sql`${pulsesTable.otxId} IN ${otxIds}`);
        for (const row of rows) {
            existing.add(row.otxId);
        }
    } catch (err) {
        log.warn('Pulse delta check failed', { error: (err as Error).message });
    }
    return existing;
}
