/**
 * Bulk Import Routes
 *
 * IOC JSON and CSV import endpoints.
 */

import { Hono } from 'hono';
import { db } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { requireRole } from '../../../../middleware/auth';
import { ValidationError } from '../../../../lib/errors';
import { createLogger } from '../../../../lib/logger';

const log = createLogger('bulk:import');

const importRoutes = new Hono();

// =============================================================================
// Types
// =============================================================================

interface ImportItem {
    value: string;
    type?: string;
    source?: string;
    severity?: string;
    tags?: string[];
}

interface ImportResult {
    success: number;
    failed: number;
    duplicates: number;
    errors: Array<{ value: string; error: string }>;
}

// IOC type detection
function detectIOCType(value: string): string | null {
    const trimmed = value.trim();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return 'ip';
    if (/^https?:\/\/.+/i.test(trimmed)) return 'url';
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return 'sha256';
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return 'sha1';
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return 'md5';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return 'email';
    if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(trimmed)) return 'domain';
    return null;
}

// =============================================================================
// JSON Import
// =============================================================================

/**
 * POST /import/iocs
 * Bulk import IOCs
 */
importRoutes.post('/iocs', requireRole('admin', 'analyst'), async (c) => {
    const body = await c.req.json();
    const items: ImportItem[] = body.items || [];
    const source = body.source || 'bulk-import';

    if (!items.length) {
        throw new ValidationError('No items provided');
    }

    if (items.length > 10000) {
        throw new ValidationError('Maximum 10,000 items per request');
    }

    const result: ImportResult = {
        success: 0,
        failed: 0,
        duplicates: 0,
        errors: [],
    };

    // Process items
    for (const item of items) {
        try {
            const type = item.type || detectIOCType(item.value);
            if (!type) {
                result.failed++;
                result.errors.push({ value: item.value, error: 'Unable to detect IOC type' });
                continue;
            }

            // Insert into database
            const [inserted] = await db.insert(iocs).values({
                type: type,
                value: item.value,
                source: item.source || source,
                severity: (item.severity || 'low') as 'low' | 'medium' | 'high' | 'critical',
                tags: item.tags || [],
                firstSeen: new Date(),
                lastSeen: new Date(),
            }).onConflictDoNothing().returning();

            // Sync to OpenSearch if inserted
            if (inserted) {
                try {
                    const { indexSingleIOC } = await import('../../../../services/opensearch');
                    await indexSingleIOC(inserted);
                } catch (searchErr) {
                    log.warn('Failed to index IOC in OpenSearch', { value: item.value, error: (searchErr as Error)?.message });
                }
            }

            result.success++;
        } catch (err) {
            result.failed++;
            result.errors.push({ value: item.value, error: (err as Error).message });
        }
    }

    return c.json({
        success: true,
        data: result,
        meta: {
            requestId: crypto.randomUUID(),
            processedAt: new Date().toISOString(),
        },
    });
});

// =============================================================================
// CSV Import
// =============================================================================

/**
 * POST /import/csv
 * Import IOCs from CSV format
 */
importRoutes.post('/csv', requireRole('admin', 'analyst'), async (c) => {
    const contentType = c.req.header('Content-Type') || '';

    if (!contentType.includes('text/csv') && !contentType.includes('multipart/form-data')) {
        throw new ValidationError('Content-Type must be text/csv');
    }

    const text = await c.req.text();
    const lines = text.trim().split('\n');

    if (lines.length < 2) {
        throw new ValidationError('CSV must have header and at least one data row');
    }

    // Parse header
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
    const valueIdx = headers.indexOf('value') !== -1 ? headers.indexOf('value') : 0;
    const typeIdx = headers.indexOf('type');
    const sourceIdx = headers.indexOf('source');
    const severityIdx = headers.indexOf('severity');

    // Parse data rows
    const items: ImportItem[] = [];
    for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].split(',').map(c => c.trim());
        if (cols.length > 0 && cols[valueIdx]) {
            items.push({
                value: cols[valueIdx],
                type: typeIdx >= 0 ? cols[typeIdx] : undefined,
                source: sourceIdx >= 0 ? cols[sourceIdx] : 'csv-import',
                severity: severityIdx >= 0 ? cols[severityIdx] : 'low',
            });
        }
    }

    return c.json({
        success: true,
        data: {
            parsed: items.length,
            message: 'CSV parsed successfully. Use JSON import for processing.',
            preview: items.slice(0, 5),
        },
    });
});

export default importRoutes;
