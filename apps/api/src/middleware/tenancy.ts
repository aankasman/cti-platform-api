/**
 * Multi-Tenancy Middleware (Database-Backed)
 *
 * Provides organization-scoped data isolation for threat intelligence.
 * Organizations are stored in PostgreSQL and cached in Redis (60s TTL).
 * Supports sharing data across organizations with proper access controls.
 */

import type { Context, Next } from 'hono';
import { db, eq, and } from '@rinjani/db';
import { organizations, organizationQuotas, userOrganizations } from '@rinjani/db';
import { cacheConnection } from '../services/redis';
import type { AuthUser } from './auth';
import { createLogger } from '../lib/logger';

const log = createLogger('Tenancy');

// ============================================================================
// Types
// ============================================================================

export interface TenantContext {
    organizationId: string;
    organizationName: string;
    plan: 'free' | 'pro' | 'enterprise';
    permissions: TenantPermission[];
    dataScope: 'organization' | 'shared' | 'global';
    quotas?: TenantQuotas;
}

export type TenantPermission =
    | 'iocs:read' | 'iocs:write' | 'iocs:delete'
    | 'vulns:read' | 'vulns:write'
    | 'actors:read' | 'actors:write'
    | 'config:read' | 'config:write'
    | 'users:manage'
    | 'export:csv' | 'export:stix'
    | 'webhooks:manage'
    | 'admin:full';

export interface TenantQuotas {
    maxIOCs: number;
    maxWebhooks: number;
    maxApiCalls: number;
    maxExportSize: number;
}

export interface Organization {
    id: string;
    name: string;
    slug: string | null;
    plan: 'free' | 'pro' | 'enterprise';
    settings: Record<string, unknown>;
    isDefault: boolean;
    createdAt: Date;
    quotas?: TenantQuotas;
}

// ============================================================================
// Redis Cache Helpers (60s TTL)
// ============================================================================

const CACHE_PREFIX = 'rjn:org:';
const CACHE_TTL = 60;

async function getCachedOrg(id: string): Promise<Organization | null> {
    try {
        const cached = await cacheConnection.get(`${CACHE_PREFIX}${id}`);
        return cached ? JSON.parse(cached) : null;
    } catch {
        return null;
    }
}

async function setCachedOrg(id: string, org: Organization): Promise<void> {
    try {
        await cacheConnection.setex(`${CACHE_PREFIX}${id}`, CACHE_TTL, JSON.stringify(org));
    } catch { /* cache write is best-effort */ }
}

async function invalidateOrgCache(id: string): Promise<void> {
    try { await cacheConnection.del(`${CACHE_PREFIX}${id}`); } catch { /* ignore */ }
}

// ============================================================================
// Database Lookups
// ============================================================================

/**
 * Fetch an organization by ID or slug from PostgreSQL.
 * Results are cached in Redis for 60 seconds.
 */
export async function getOrganization(idOrSlug: string): Promise<Organization | undefined> {
    // 1. Check Redis cache first
    const cached = await getCachedOrg(idOrSlug);
    if (cached) return cached;

    // 2. Query database — try by UUID first, then by slug
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(idOrSlug);

    let row;
    if (isUUID) {
        const rows = await db.select().from(organizations).where(eq(organizations.id, idOrSlug)).limit(1);
        row = rows[0];
    }

    if (!row) {
        const slugRows = await db.select().from(organizations).where(eq(organizations.slug, idOrSlug)).limit(1);
        row = slugRows[0];
    }

    if (!row) return undefined;

    // 3. Fetch quotas
    const quotaRows = await db.select().from(organizationQuotas).where(eq(organizationQuotas.orgId, row.id)).limit(1);

    const org: Organization = {
        id: row.id,
        name: row.name,
        slug: row.slug,
        plan: row.plan,
        settings: (row.settings as Record<string, unknown>) || {},
        isDefault: row.isDefault ?? false,
        createdAt: row.createdAt,
        quotas: quotaRows[0] ? {
            maxIOCs: quotaRows[0].maxIocs,
            maxWebhooks: quotaRows[0].maxWebhooks,
            maxApiCalls: quotaRows[0].maxApiCalls,
            maxExportSize: quotaRows[0].maxExportSize,
        } : undefined,
    };

    // 4. Cache the result
    await setCachedOrg(row.id, org);
    if (row.slug) await setCachedOrg(row.slug, org);

    return org;
}

/**
 * List all organizations from the database.
 */
export async function listOrganizations(): Promise<Organization[]> {
    const rows = await db.select().from(organizations);
    return rows.map(row => ({
        id: row.id,
        name: row.name,
        slug: row.slug,
        plan: row.plan,
        settings: (row.settings as Record<string, unknown>) || {},
        isDefault: row.isDefault ?? false,
        createdAt: row.createdAt,
    }));
}

/**
 * Create a new organization with default quotas for its plan.
 */
export async function createOrganization(data: {
    name: string;
    slug: string;
    plan?: 'free' | 'pro' | 'enterprise';
}): Promise<Organization> {
    const plan = data.plan || 'free';
    const planQuotas = PLAN_QUOTAS[plan];

    const [row] = await db.insert(organizations).values({
        name: data.name,
        slug: data.slug,
        plan,
    }).returning();

    // Create quotas for the org
    await db.insert(organizationQuotas).values({
        orgId: row.id,
        maxIocs: planQuotas.maxIOCs,
        maxWebhooks: planQuotas.maxWebhooks,
        maxApiCalls: planQuotas.maxApiCalls,
        maxExportSize: planQuotas.maxExportSize,
    });

    const org: Organization = {
        id: row.id,
        name: row.name,
        slug: row.slug,
        plan: row.plan,
        settings: {},
        isDefault: false,
        createdAt: row.createdAt,
        quotas: planQuotas,
    };

    await setCachedOrg(row.id, org);
    return org;
}

/**
 * Update organization plan and adjust quotas.
 */
export async function updateOrganizationPlan(orgId: string, plan: 'free' | 'pro' | 'enterprise'): Promise<boolean> {
    const planQuotas = PLAN_QUOTAS[plan];

    await db.update(organizations).set({ plan, updatedAt: new Date() }).where(eq(organizations.id, orgId));
    await db.update(organizationQuotas).set({
        maxIocs: planQuotas.maxIOCs,
        maxWebhooks: planQuotas.maxWebhooks,
        maxApiCalls: planQuotas.maxApiCalls,
        maxExportSize: planQuotas.maxExportSize,
    }).where(eq(organizationQuotas.orgId, orgId));

    await invalidateOrgCache(orgId);
    return true;
}

// ============================================================================
// Default Quotas by Plan
// ============================================================================

const PLAN_QUOTAS: Record<string, TenantQuotas> = {
    free: { maxIOCs: 10000, maxWebhooks: 3, maxApiCalls: 10000, maxExportSize: 1000 },
    pro: { maxIOCs: 100000, maxWebhooks: 20, maxApiCalls: 100000, maxExportSize: 50000 },
    enterprise: { maxIOCs: -1, maxWebhooks: -1, maxApiCalls: -1, maxExportSize: -1 }, // unlimited
};

// ============================================================================
// Middleware
// ============================================================================

/**
 * Multi-tenancy middleware.
 * Extracts organization context from request and validates access.
 */
export function multiTenancy() {
    return async (c: Context, next: Next) => {
        const user = c.get('user') as AuthUser | undefined;
        const orgId = getOrgFromUser(c);

        if (!orgId) {
            // No org context — set global scope
            c.set('tenant' as never, {
                organizationId: 'global',
                organizationName: 'Global',
                plan: 'enterprise',
                permissions: ['admin:full'] as TenantPermission[],
                dataScope: 'global',
            } satisfies TenantContext);
            await next();
            return;
        }

        const org = await getOrganization(orgId);
        if (!org) {
            return c.json({ success: false, error: 'Organization not found' }, 404);
        }

        const permissions = getUserPermissions(user, org);
        const dataScope = determineDataScope(user, org);

        const tenantCtx: TenantContext = {
            organizationId: org.id,
            organizationName: org.name,
            plan: org.plan,
            permissions,
            dataScope,
            quotas: org.quotas,
        };

        c.set('tenant' as never, tenantCtx);
        c.header('X-Organization-Id', org.id);
        c.header('X-Organization-Name', org.name);

        await next();
    };
}

/**
 * Require specific tenant permission.
 */
export function requireTenantPermission(...requiredPermissions: TenantPermission[]) {
    return async (c: Context, next: Next) => {
        const tenant = c.get('tenant' as never) as TenantContext | undefined;
        if (!tenant) {
            return c.json({ success: false, error: 'No organization context' }, 403);
        }

        if (tenant.permissions.includes('admin:full')) {
            await next();
            return;
        }

        const hasPermission = requiredPermissions.some(p => tenant.permissions.includes(p));
        if (!hasPermission) {
            return c.json({
                success: false,
                error: `Missing required permission: ${requiredPermissions.join(' or ')}`,
            }, 403);
        }

        await next();
    };
}

/**
 * Check quota before allowing operation.
 */
export function checkQuota(quotaType: keyof TenantQuotas) {
    return async (c: Context, next: Next) => {
        const tenant = c.get('tenant' as never) as TenantContext | undefined;
        if (!tenant?.quotas) {
            await next();
            return;
        }

        const limit = tenant.quotas[quotaType];
        if (limit === -1) {
            // Unlimited
            await next();
            return;
        }

        const currentUsage = await getCurrentUsage(tenant.organizationId, quotaType);
        if (currentUsage >= limit) {
            return c.json({
                success: false,
                error: `Quota exceeded for ${quotaType}. Current: ${currentUsage}, Limit: ${limit}. Upgrade your plan.`,
                quota: { type: quotaType, current: currentUsage, limit, plan: tenant.plan },
            }, 429);
        }

        await next();
    };
}

// ============================================================================
// Helper Functions
// ============================================================================

function getOrgFromUser(c: Context): string | null {
    const user = c.get('user') as AuthUser | undefined;
    return c.req.header('X-Organization-Id') || user?.tenantId || null;
}

function getUserPermissions(user: AuthUser | undefined, org: Organization): TenantPermission[] {
    if (!user) return ['iocs:read', 'vulns:read', 'actors:read'];

    if (user.role === 'admin') return ['admin:full'];

    const rolePermissions: Record<string, TenantPermission[]> = {
        analyst: ['iocs:read', 'iocs:write', 'vulns:read', 'vulns:write', 'actors:read', 'actors:write', 'export:csv', 'export:stix'],
        developer: ['iocs:read', 'vulns:read', 'actors:read', 'config:read', 'webhooks:manage'],
        auditor: ['iocs:read', 'vulns:read', 'actors:read', 'config:read'],
        viewer: ['iocs:read', 'vulns:read', 'actors:read'],
    };

    return rolePermissions[user.role] || rolePermissions.viewer;
}

function determineDataScope(user: AuthUser | undefined, org: Organization): 'organization' | 'shared' | 'global' {
    if (!user) return 'global';
    if (user.role === 'admin') return 'global';
    if (org.plan === 'enterprise') return 'shared';
    return 'organization';
}

async function getCurrentUsage(orgId: string, quotaType: keyof TenantQuotas): Promise<number> {
    // In production, this would query actual counts from the respective tables
    // For now, return 0 (under quota)
    return 0;
}

/**
 * Get user's tenant memberships from the database.
 */
export async function getUserTenants(userId: string) {
    const memberships = await db
        .select({
            orgId: userOrganizations.organizationId,
            role: userOrganizations.role,
            orgName: organizations.name,
            orgSlug: organizations.slug,
            orgPlan: organizations.plan,
        })
        .from(userOrganizations)
        .innerJoin(organizations, eq(userOrganizations.organizationId, organizations.id))
        .where(eq(userOrganizations.userId, userId));

    return memberships.map(m => ({
        organizationId: m.orgId,
        name: m.orgName,
        slug: m.orgSlug,
        plan: m.orgPlan,
        role: m.role,
    }));
}
