/**
 * Audit Service
 * 
 * Provides audit logging for all entity changes with data provenance tracking.
 */

import { createHash } from 'crypto';

// Context type for request metadata extraction (avoids Hono dependency in core)
interface RequestContext {
    get(key: string): any;
    req: {
        header(name: string): string | undefined;
    };
}

// ============================================================================
// Types
// ============================================================================

export type AuditAction = 'create' | 'update' | 'delete' | 'merge' | 'enrich';
export type EntityType = 'ioc' | 'vulnerability' | 'threat_actor' | 'pulse' | 'indicator' | 'malware';

export interface AuditEntry {
    id: string;
    entityType: EntityType;
    entityId: string;
    action: AuditAction;
    userId?: string;
    apiKeyId?: string;
    source: string;
    changes?: {
        before?: Record<string, unknown>;
        after?: Record<string, unknown>;
        diff?: Array<{ field: string; old: unknown; new: unknown }>;
    };
    metadata?: {
        ip?: string;
        userAgent?: string;
        requestId?: string;
        reason?: string;
    };
    createdAt: Date;
}

// ============================================================================
// In-Memory Audit Log (for demo - replace with DB in production)
// ============================================================================

const auditLog: AuditEntry[] = [];
const MAX_AUDIT_SIZE = 10000;

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Generate a hash of the data for integrity verification
 */
export function generateDataHash(data: unknown): string {
    const json = JSON.stringify(data, Object.keys(data as object).sort());
    return createHash('sha256').update(json).digest('hex');
}

/**
 * Calculate diff between two objects
 */
export function calculateDiff(before: Record<string, unknown>, after: Record<string, unknown>): Array<{ field: string; old: unknown; new: unknown }> {
    const diff: Array<{ field: string; old: unknown; new: unknown }> = [];
    const allKeys = new Set([...Object.keys(before), ...Object.keys(after)]);

    for (const key of allKeys) {
        const oldVal = before[key];
        const newVal = after[key];

        if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
            diff.push({ field: key, old: oldVal, new: newVal });
        }
    }

    return diff;
}

/**
 * Log an audit entry
 */
export function logAudit(entry: Omit<AuditEntry, 'id' | 'createdAt'>): AuditEntry {
    const fullEntry: AuditEntry = {
        ...entry,
        id: crypto.randomUUID(),
        createdAt: new Date(),
    };

    // Add to in-memory log (FIFO if exceeds max)
    if (auditLog.length >= MAX_AUDIT_SIZE) {
        auditLog.shift();
    }
    auditLog.push(fullEntry);

    return fullEntry;
}

/**
 * Log entity creation
 */
export function auditCreate(
    entityType: EntityType,
    entityId: string,
    data: Record<string, unknown>,
    context?: { userId?: string; source?: string; metadata?: AuditEntry['metadata'] }
): AuditEntry {
    return logAudit({
        entityType,
        entityId,
        action: 'create',
        userId: context?.userId,
        source: context?.source || 'api',
        changes: { after: data },
        metadata: context?.metadata,
    });
}

/**
 * Log entity update
 */
export function auditUpdate(
    entityType: EntityType,
    entityId: string,
    before: Record<string, unknown>,
    after: Record<string, unknown>,
    context?: { userId?: string; source?: string; metadata?: AuditEntry['metadata'] }
): AuditEntry {
    return logAudit({
        entityType,
        entityId,
        action: 'update',
        userId: context?.userId,
        source: context?.source || 'api',
        changes: {
            before,
            after,
            diff: calculateDiff(before, after),
        },
        metadata: context?.metadata,
    });
}

/**
 * Log entity deletion
 */
export function auditDelete(
    entityType: EntityType,
    entityId: string,
    data: Record<string, unknown>,
    context?: { userId?: string; source?: string; metadata?: AuditEntry['metadata'] }
): AuditEntry {
    return logAudit({
        entityType,
        entityId,
        action: 'delete',
        userId: context?.userId,
        source: context?.source || 'api',
        changes: { before: data },
        metadata: context?.metadata,
    });
}

/**
 * Log entity merge (deduplication)
 */
export function auditMerge(
    entityType: EntityType,
    entityId: string,
    mergedFrom: Record<string, unknown>,
    result: Record<string, unknown>,
    context?: { userId?: string; source?: string; metadata?: AuditEntry['metadata'] }
): AuditEntry {
    return logAudit({
        entityType,
        entityId,
        action: 'merge',
        userId: context?.userId,
        source: context?.source || 'system',
        changes: {
            before: mergedFrom,
            after: result,
        },
        metadata: context?.metadata,
    });
}

// ============================================================================
// Query Functions
// ============================================================================

export interface AuditQueryOptions {
    entityType?: EntityType;
    entityId?: string;
    action?: AuditAction;
    userId?: string;
    source?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
}

/**
 * Query audit logs with filters
 */
export function queryAuditLogs(options: AuditQueryOptions = {}): { entries: AuditEntry[]; total: number } {
    let filtered = [...auditLog];

    if (options.entityType) {
        filtered = filtered.filter(e => e.entityType === options.entityType);
    }
    if (options.entityId) {
        filtered = filtered.filter(e => e.entityId === options.entityId);
    }
    if (options.action) {
        filtered = filtered.filter(e => e.action === options.action);
    }
    if (options.userId) {
        filtered = filtered.filter(e => e.userId === options.userId);
    }
    if (options.source) {
        filtered = filtered.filter(e => e.source === options.source);
    }
    if (options.startDate) {
        filtered = filtered.filter(e => e.createdAt >= options.startDate!);
    }
    if (options.endDate) {
        filtered = filtered.filter(e => e.createdAt <= options.endDate!);
    }

    // Sort by newest first
    filtered.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const total = filtered.length;
    const offset = options.offset || 0;
    const limit = options.limit || 50;

    return {
        entries: filtered.slice(offset, offset + limit),
        total,
    };
}

/**
 * Get entity history (all changes to a specific entity)
 */
export function getEntityHistory(entityType: EntityType, entityId: string): AuditEntry[] {
    return auditLog
        .filter(e => e.entityType === entityType && e.entityId === entityId)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
}

/**
 * Get audit stats
 */
export function getAuditStats(): {
    totalEntries: number;
    byAction: Record<AuditAction, number>;
    byEntityType: Record<EntityType, number>;
    recentActivity: number;
} {
    const byAction: Record<AuditAction, number> = { create: 0, update: 0, delete: 0, merge: 0, enrich: 0 };
    const byEntityType: Record<EntityType, number> = { ioc: 0, vulnerability: 0, threat_actor: 0, pulse: 0, indicator: 0, malware: 0 };

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    let recentActivity = 0;

    for (const entry of auditLog) {
        byAction[entry.action]++;
        byEntityType[entry.entityType]++;
        if (entry.createdAt >= oneHourAgo) recentActivity++;
    }

    return {
        totalEntries: auditLog.length,
        byAction,
        byEntityType,
        recentActivity,
    };
}

// ============================================================================
// Hono Context Helper
// ============================================================================

/**
 * Extract audit metadata from request context
 */
export function getAuditContext(c: RequestContext): { userId?: string; metadata: AuditEntry['metadata'] } {
    const user = c.get('user');

    return {
        userId: user?.id,
        metadata: {
            ip: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP'),
            userAgent: c.req.header('User-Agent'),
            requestId: c.req.header('X-Request-Id') || crypto.randomUUID(),
        },
    };
}
