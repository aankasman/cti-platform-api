/**
 * Export — Helper Functions (filters, CSV generators, STIX)
 */

import { iocs, vulnerabilities } from '@rinjani/db/schema';
import { eq, gte, lte, or, type SQL } from '@rinjani/db';

// ============================================================================
// Filter Builders
// ============================================================================

export function buildIOCFilters(filters: Record<string, unknown>): SQL[] {
    const conditions: SQL[] = [];

    if (filters.type && Array.isArray(filters.type)) {
        conditions.push(or(...filters.type.map((t: string) => eq(iocs.type, t)))!);
    }
    if (filters.source && Array.isArray(filters.source)) {
        conditions.push(or(...filters.source.map((s: string) => eq(iocs.source, s)))!);
    }
    if (filters.severity && Array.isArray(filters.severity)) {
        conditions.push(or(...filters.severity.map((s: string) => eq(iocs.severity, s)))!);
    }
    if (filters.dateFrom) {
        conditions.push(gte(iocs.lastSeen, new Date(filters.dateFrom as string)));
    }
    if (filters.dateTo) {
        conditions.push(lte(iocs.lastSeen, new Date(filters.dateTo as string)));
    }

    return conditions;
}

export function buildVulnFilters(filters: Record<string, unknown>): SQL[] {
    const conditions: SQL[] = [];

    if (filters.severity && Array.isArray(filters.severity)) {
        conditions.push(or(...filters.severity.map((s: string) => eq(vulnerabilities.severity, s)))!);
    }
    if (filters.exploited !== undefined) {
        conditions.push(eq(vulnerabilities.isExploited, filters.exploited as boolean));
    }
    if (filters.dateFrom) {
        conditions.push(gte(vulnerabilities.publishedDate, new Date(filters.dateFrom as string)));
    }
    if (filters.dateTo) {
        conditions.push(lte(vulnerabilities.publishedDate, new Date(filters.dateTo as string)));
    }

    return conditions;
}

// ============================================================================
// CSV Generators
// ============================================================================

export function generateIOCCSV(items: Record<string, unknown>[]): string {
    const headers = ['Type', 'Value', 'Source', 'Threat Type', 'Severity', 'Confidence', 'First Seen', 'Last Seen', 'Tags'];
    const rows = items.map(ioc => [
        ioc.type || '',
        ioc.value || '',
        ioc.source || '',
        ioc.threatType || '',
        ioc.severity || '',
        ioc.confidence || '',
        ioc.firstSeen ? new Date(ioc.firstSeen as string).toISOString() : '',
        ioc.lastSeen ? new Date(ioc.lastSeen as string).toISOString() : '',
        Array.isArray(ioc.tags) ? ioc.tags.join(';') : '',
    ]);

    return [headers, ...rows]
        .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        .join('\n');
}

export function generateVulnCSV(items: Record<string, unknown>[]): string {
    const headers = ['CVE ID', 'Vendor', 'Product', 'Severity', 'CVSS Score', 'Published Date', 'Is Exploited', 'Description'];
    const rows = items.map(vuln => [
        vuln.cveId || '',
        vuln.vendorProject || '',
        vuln.product || '',
        vuln.severity || '',
        vuln.cvssScore || '',
        vuln.publishedDate ? new Date(vuln.publishedDate as string).toISOString() : '',
        vuln.isExploited ? 'Yes' : 'No',
        vuln.description || '',
    ]);

    return [headers, ...rows]
        .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        .join('\n');
}

// ============================================================================
// STIX Generators
// ============================================================================

export function generateSTIXBundle(items: Record<string, unknown>[]): Record<string, unknown> {
    const objects = items.map(ioc => {
        const stixType = getSTIXType(ioc.type as string);

        return {
            type: 'indicator',
            spec_version: '2.1',
            id: `indicator--${crypto.randomUUID()}`,
            created: ioc.firstSeen,
            modified: ioc.lastSeen,
            name: ioc.value,
            pattern: `[${stixType}:value = '${ioc.value}']`,
            pattern_type: 'stix',
            valid_from: ioc.firstSeen,
            labels: ioc.tags || [],
            confidence: ioc.confidence || 50,
        };
    });

    return {
        type: 'bundle',
        id: `bundle--${crypto.randomUUID()}`,
        objects,
    };
}

export function getSTIXType(iocType: string): string {
    const typeMap: Record<string, string> = {
        'ip': 'ipv4-addr',
        'domain': 'domain-name',
        'url': 'url',
        'hash': 'file',
    };
    return typeMap[iocType] || 'indicator';
}


// Maximum allowed export limits
export const MAX_EXPORT_LIMIT = 10000;
export const MAX_STIX_LIMIT = 1000;
