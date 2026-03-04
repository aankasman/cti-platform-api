/**
 * Advanced Vulnerability Search Route
 */

import { Hono } from 'hono';
import { and, count, db, desc, eq, gte, like, lte, or, type SQL } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { ValidationError } from '../../lib/errors';
import { VulnSearchSchema } from './schemas';

const vulnSearch = new Hono();

/**
 * POST /vulnerabilities
 * Advanced vulnerability search with filters
 */
vulnSearch.post('/', async (c) => {
    const body = await c.req.json();

    // Zod validation
    const parsed = VulnSearchSchema.safeParse(body);
    if (!parsed.success) {
        const issues = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`);
        throw new ValidationError(`Invalid search request: ${issues.join('; ')}`);
    }

    const { query, filters, sort, pagination } = parsed.data;

    const conditions: (SQL | undefined)[] = [];

    // Full-text search
    if (query) {
        conditions.push(
            or(
                like(vulnerabilities.cveId, `%${query}%`),
                like(vulnerabilities.description, `%${query}%`),
                like(vulnerabilities.vendorProject, `%${query}%`)
            )
        );
    }

    // Severity filter
    if (filters.severity && Array.isArray(filters.severity) && filters.severity.length > 0) {
        conditions.push(or(...filters.severity.map((s: string) => eq(vulnerabilities.severity, s))));
    }

    // Exploited filter
    if (filters.exploited !== undefined) {
        // CISA KEV entries have isExploited flag
        conditions.push(eq(vulnerabilities.isExploited, filters.exploited));
    }

    // CVSS score range
    if (filters.minCvss) {
        conditions.push(gte(vulnerabilities.cvssScore, String(filters.minCvss)));
    }
    if (filters.maxCvss) {
        conditions.push(lte(vulnerabilities.cvssScore, String(filters.maxCvss)));
    }

    // Date range
    if (filters.dateFrom) {
        conditions.push(gte(vulnerabilities.publishedDate, new Date(filters.dateFrom)));
    }
    if (filters.dateTo) {
        conditions.push(lte(vulnerabilities.publishedDate, new Date(filters.dateTo)));
    }

    // Vendor filter
    if (filters.vendor) {
        conditions.push(like(vulnerabilities.vendorProject, `%${filters.vendor}%`));
    }

    // Build query
    let query_builder = db.select().from(vulnerabilities);

    if (conditions.length > 0) {
        query_builder = query_builder.where(and(...conditions)) as typeof query_builder;
    }

    // Sorting
    const validSortFields = ['cveId', 'description', 'cvssScore', 'severity', 'isExploited', 'vendorProject', 'product', 'publishedDate', 'lastModified', 'createdAt'] as const;
    const sortFieldName = validSortFields.includes(sort.field as typeof validSortFields[number]) ? sort.field as typeof validSortFields[number] : 'publishedDate' as const;
    const sortColumn = vulnerabilities[sortFieldName];
    const sortedQuery = sort.order === 'asc'
        ? query_builder.orderBy(sortColumn)
        : query_builder.orderBy(desc(sortColumn));

    // Pagination
    const offset = (pagination.page - 1) * pagination.limit;
    const items = await sortedQuery
        .limit(pagination.limit)
        .offset(offset);

    // Count total
    let countQuery = db.select({ total: count() }).from(vulnerabilities);
    if (conditions.length > 0) {
        countQuery = countQuery.where(and(...conditions)) as typeof countQuery;
    }
    const [{ total }] = await countQuery;

    return c.json({
        success: true,
        data: {
            items,
            pagination: {
                page: pagination.page,
                limit: pagination.limit,
                total,
                pages: Math.ceil(total / pagination.limit),
            },
        },
    });
});

export default vulnSearch;
