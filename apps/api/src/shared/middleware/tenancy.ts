/**
 * Multi-Tenancy Middleware
 * 
 * Provides organization-scoped data isolation for threat intelligence.
 * Supports sharing data across organizations with proper access controls.
 */

import type { Context, Next } from 'hono';
import { db } from '@rinjani/db';
import type { AuthUser } from './auth';

// ============================================================================
// Types
// ============================================================================

export interface TenantContext {
    organizationId: string;
    organizationName: string;
    permissions: TenantPermission[];
    dataScope: 'organization' | 'shared' | 'global';
    quotas?: TenantQuotas;
}

export type TenantPermission =
    | 'read:iocs'
    | 'write:iocs'
    | 'read:vulnerabilities'
    | 'write:vulnerabilities'
    | 'read:threats'
    | 'write:threats'
    | 'admin:organization'
    | 'share:data';

export interface TenantQuotas {
    maxIOCs: number;
    maxWebhooks: number;
    maxApiCalls: number;
    maxExportSize: number;
}

// ============================================================================
// In-Memory Organization Store (replace with DB in production)
// ============================================================================

interface Organization {
    id: string;
    name: string;
    slug: string;
    plan: 'free' | 'pro' | 'enterprise';
    quotas: TenantQuotas;
    settings: Record<string, unknown>;
    createdAt: Date;
}

const organizations = new Map<string, Organization>();

// Default quotas by plan
const PLAN_QUOTAS: Record<string, TenantQuotas> = {
    free: {
        maxIOCs: 10000,
        maxWebhooks: 3,
        maxApiCalls: 10000,
        maxExportSize: 1000,
    },
    pro: {
        maxIOCs: 100000,
        maxWebhooks: 10,
        maxApiCalls: 100000,
        maxExportSize: 10000,
    },
    enterprise: {
        maxIOCs: -1, // unlimited
        maxWebhooks: -1,
        maxApiCalls: -1,
        maxExportSize: -1,
    },
};

// Initialize with default organization
organizations.set('default', {
    id: 'default',
    name: 'Default Organization',
    slug: 'default',
    plan: 'enterprise',
    quotas: PLAN_QUOTAS.enterprise,
    settings: {},
    createdAt: new Date('2026-01-01'),
});

// ============================================================================
// Middleware
// ============================================================================

/**
 * Multi-tenancy middleware
 * Extracts organization context from request and validates access
 */
export function multiTenancy() {
    return async (c: Context, next: Next) => {
        // Get organization from various sources
        const orgId =
            c.req.header('X-Organization-Id') ||
            c.req.query('org') ||
            getOrgFromUser(c) ||
            'default';

        const org = organizations.get(orgId);

        if (!org) {
            return c.json({
                success: false,
                error: {
                    code: 'ORGANIZATION_NOT_FOUND',
                    message: `Organization ${orgId} not found`,
                },
            }, 404);
        }

        // Build tenant context
        const user = c.get('user');
        const permissions = getUserPermissions(user, org);

        const tenantContext: TenantContext = {
            organizationId: org.id,
            organizationName: org.name,
            permissions,
            dataScope: determineDataScope(user, org),
            quotas: org.quotas,
        };

        // Set tenant context on request
        c.set('tenant', tenantContext);
        c.set('organizationId', org.id);

        // Add organization header to response
        c.header('X-Organization-Id', org.id);
        c.header('X-Organization-Name', org.name);

        await next();
    };
}

/**
 * Require specific tenant permission
 */
export function requireTenantPermission(...requiredPermissions: TenantPermission[]) {
    return async (c: Context, next: Next) => {
        const tenant = c.get('tenant') as TenantContext | undefined;

        if (!tenant) {
            return c.json({
                success: false,
                error: {
                    code: 'NO_TENANT_CONTEXT',
                    message: 'Organization context required',
                },
            }, 403);
        }

        const hasPermission = requiredPermissions.some(p => tenant.permissions.includes(p));

        if (!hasPermission) {
            return c.json({
                success: false,
                error: {
                    code: 'INSUFFICIENT_PERMISSIONS',
                    message: `Required permissions: ${requiredPermissions.join(' or ')}`,
                    organizationId: tenant.organizationId,
                },
            }, 403);
        }

        await next();
    };
}

/**
 * Check quota before allowing operation
 */
export function checkQuota(quotaType: keyof TenantQuotas) {
    return async (c: Context, next: Next) => {
        const tenant = c.get('tenant') as TenantContext | undefined;

        if (!tenant || !tenant.quotas) {
            await next();
            return;
        }

        const limit = tenant.quotas[quotaType];

        // -1 means unlimited
        if (limit === -1) {
            await next();
            return;
        }

        // Get current usage (would query DB in production)
        const currentUsage = await getCurrentUsage(tenant.organizationId, quotaType);

        if (currentUsage >= limit) {
            return c.json({
                success: false,
                error: {
                    code: 'QUOTA_EXCEEDED',
                    message: `Quota exceeded for ${quotaType}. Limit: ${limit}, Current: ${currentUsage}`,
                    upgrade: 'Contact support to upgrade your plan',
                },
            }, 429);
        }

        await next();
    };
}

// ============================================================================
// Helper Functions
// ============================================================================

function getOrgFromUser(c: Context): string | null {
    const user = c.get('user') as { organizationId?: string } | undefined;
    return user?.organizationId || null;
}

function getUserPermissions(user: AuthUser | undefined, org: Organization): TenantPermission[] {
    if (!user) {
        // Anonymous users get read-only access
        return ['read:iocs', 'read:vulnerabilities', 'read:threats'];
    }

    // Admin gets all permissions
    if (user.role === 'admin') {
        return [
            'read:iocs', 'write:iocs',
            'read:vulnerabilities', 'write:vulnerabilities',
            'read:threats', 'write:threats',
            'admin:organization', 'share:data',
        ];
    }

    // Analyst gets read/write but no admin
    if (user.role === 'analyst') {
        return [
            'read:iocs', 'write:iocs',
            'read:vulnerabilities', 'write:vulnerabilities',
            'read:threats', 'write:threats',
            'share:data',
        ];
    }

    // Viewer gets read-only
    return ['read:iocs', 'read:vulnerabilities', 'read:threats'];
}

function determineDataScope(user: AuthUser | undefined, org: Organization): 'organization' | 'shared' | 'global' {
    // Enterprise can see global data
    if (org.plan === 'enterprise') return 'global';

    // Pro can see shared data
    if (org.plan === 'pro') return 'shared';

    // Free is organization-scoped only
    return 'organization';
}

async function getCurrentUsage(orgId: string, quotaType: keyof TenantQuotas): Promise<number> {
    // In production, this would query the database
    // For now, return mock values
    return 0;
}

// ============================================================================
// Organization Management Functions
// ============================================================================

export function createOrganization(data: {
    name: string;
    slug: string;
    plan?: 'free' | 'pro' | 'enterprise';
}): Organization {
    const id = crypto.randomUUID();
    const plan = data.plan || 'free';

    const org: Organization = {
        id,
        name: data.name,
        slug: data.slug,
        plan,
        quotas: PLAN_QUOTAS[plan],
        settings: {},
        createdAt: new Date(),
    };

    organizations.set(id, org);
    organizations.set(data.slug, org); // Also index by slug

    return org;
}

export function getOrganization(idOrSlug: string): Organization | undefined {
    return organizations.get(idOrSlug);
}

export function listOrganizations(): Organization[] {
    const seen = new Set<string>();
    const result: Organization[] = [];

    for (const org of organizations.values()) {
        if (!seen.has(org.id)) {
            seen.add(org.id);
            result.push(org);
        }
    }

    return result;
}

export function updateOrganizationPlan(orgId: string, plan: 'free' | 'pro' | 'enterprise'): boolean {
    const org = organizations.get(orgId);
    if (!org) return false;

    org.plan = plan;
    org.quotas = PLAN_QUOTAS[plan];

    return true;
}
