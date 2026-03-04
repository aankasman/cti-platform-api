/**
 * Advanced IOC Search Route
 */

import { Hono } from 'hono';
import { and, count, db, desc, eq, gte, like, lte, or, type SQL } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { ValidationError } from '../../lib/errors';
import { IOCSearchSchema } from './schemas';

const iocSearch = new Hono();

/**
 * POST /iocs
 * Advanced IOC search with multiple filters and aggregations
 */
iocSearch.post('/', async (c) => {
    const body = await c.req.json();

    // Zod validation
    const parsed = IOCSearchSchema.safeParse(body);
    if (!parsed.success) {
        const issues = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`);
        throw new ValidationError(`Invalid search request: ${issues.join('; ')}`);
    }

    const { query, filters, sort, pagination, aggregations } = parsed.data;

    const conditions: (SQL | undefined)[] = [];

    // Full-text search on value
    if (query) {
        conditions.push(like(iocs.value, `%${query}%`));
    }

    // Type filter (multiple)
    if (filters.type && Array.isArray(filters.type) && filters.type.length > 0) {
        conditions.push(or(...filters.type.map((t: string) => eq(iocs.type, t))));
    }

    // Source filter (multiple)
    if (filters.source && Array.isArray(filters.source) && filters.source.length > 0) {
        conditions.push(or(...filters.source.map((s: string) => eq(iocs.source, s))));
    }

    // Severity filter (multiple)
    if (filters.severity && Array.isArray(filters.severity) && filters.severity.length > 0) {
        conditions.push(or(...filters.severity.map((s: string) => eq(iocs.severity, s))));
    }

    // Threat type filter
    if (filters.threatType) {
        conditions.push(eq(iocs.threatType, filters.threatType));
    }

    // Confidence range
    if (filters.minConfidence) {
        conditions.push(gte(iocs.confidence, filters.minConfidence));
    }
    if (filters.maxConfidence) {
        conditions.push(lte(iocs.confidence, filters.maxConfidence));
    }

    // Date range
    if (filters.dateFrom) {
        conditions.push(gte(iocs.lastSeen, new Date(filters.dateFrom)));
    }
    if (filters.dateTo) {
        conditions.push(lte(iocs.lastSeen, new Date(filters.dateTo)));
    }

    // Build query
    let query_builder = db.select().from(iocs);

    if (conditions.length > 0) {
        query_builder = query_builder.where(and(...conditions)) as typeof query_builder;
    }

    // Sorting
    const validSortFields = ['type', 'value', 'source', 'threatType', 'confidence', 'severity', 'firstSeen', 'lastSeen', 'createdAt', 'updatedAt'] as const;
    const sortFieldName = validSortFields.includes(sort.field as typeof validSortFields[number]) ? sort.field as typeof validSortFields[number] : 'lastSeen' as const;
    const sortColumn = iocs[sortFieldName];
    const sortedQuery = sort.order === 'asc'
        ? query_builder.orderBy(sortColumn)
        : query_builder.orderBy(desc(sortColumn));

    // Pagination
    const offset = (pagination.page - 1) * pagination.limit;
    const items = await sortedQuery
        .limit(pagination.limit)
        .offset(offset);

    // Count total
    let countQuery = db.select({ total: count() }).from(iocs);
    if (conditions.length > 0) {
        countQuery = countQuery.where(and(...conditions)) as typeof countQuery;
    }
    const [{ total }] = await countQuery;

    // Aggregations (if requested)
    let aggs = null;
    if (aggregations) {
        aggs = await getIOCAggregations(conditions);
    }

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
            aggregations: aggs,
        },
    });
});

async function getIOCAggregations(conditions: (SQL | undefined)[]) {
    let baseQuery = db.select({
        type: iocs.type,
        count: count(),
    }).from(iocs);

    if (conditions.length > 0) {
        baseQuery = baseQuery.where(and(...conditions)) as typeof baseQuery;
    }

    const byType = await baseQuery.groupBy(iocs.type);

    let sourceQuery = db.select({
        source: iocs.source,
        count: count(),
    }).from(iocs);

    if (conditions.length > 0) {
        sourceQuery = sourceQuery.where(and(...conditions)) as typeof sourceQuery;
    }

    const bySource = await sourceQuery.groupBy(iocs.source);

    let severityQuery = db.select({
        severity: iocs.severity,
        count: count(),
    }).from(iocs);

    if (conditions.length > 0) {
        severityQuery = severityQuery.where(and(...conditions)) as typeof severityQuery;
    }

    const bySeverity = await severityQuery.groupBy(iocs.severity);

    return {
        byType,
        bySource,
        bySeverity,
    };
}

export default iocSearch;
