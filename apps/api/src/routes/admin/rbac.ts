/**
 * RBAC Admin Routes — /admin/rbac/*
 *
 * Provides endpoints for managing role-based access control:
 * - Route policies (route → permission mappings)
 * - Access matrix (role × permission group grid)
 * - Keycloak role mapping
 * - RBAC audit log
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import {
    getRoutePolicies,
    getRouteGroups,
    buildAccessMatrix,
    getKeycloakMapping,
    setKeycloakMapping,
    saveKeycloakMappingToRedis,
    invalidateRbacCache,
} from '../../services/rbacService';
import {
    listRoles,
    getRoleById,
    updateRole,
    listPermissionModules,
} from '../../services/userService';
import { createLogger } from '../../lib/logger';

const log = createLogger('RBACAdmin');
const router = new Hono();

// All RBAC admin routes require admin role
router.use('*', requireAuth, requireRole('admin'));

// ============================================================================
// Route Policies
// ============================================================================

/** GET /admin/rbac/policies — List all route→permission mappings */
router.get('/policies', (c) => {
    const policies = getRoutePolicies();
    const groups = getRouteGroups();
    return c.json({
        success: true,
        policies,
        groups,
        total: policies.length,
    });
});

// ============================================================================
// Access Matrix
// ============================================================================

/** GET /admin/rbac/matrix — Full role×permission access matrix */
router.get('/matrix', async (c) => {
    const matrix = await buildAccessMatrix();
    return c.json({
        success: true,
        ...matrix,
    });
});

// ============================================================================
// Role Management (with permission editing)
// ============================================================================

/** GET /admin/rbac/roles — List all roles with permissions */
router.get('/roles', async (c) => {
    const roles = await listRoles();
    const permissionModules = await listPermissionModules();
    return c.json({
        success: true,
        roles,
        permissionModules,
    });
});

/** GET /admin/rbac/roles/:id — Get a single role */
router.get('/roles/:id', async (c) => {
    const role = await getRoleById(c.req.param('id'));
    if (!role) {
        return c.json({ success: false, error: 'Role not found' }, 404);
    }
    return c.json({ success: true, role });
});

/** PUT /admin/rbac/roles/:id/permissions — Update role permissions */
router.put('/roles/:id/permissions', async (c) => {
    const id = c.req.param('id');
    const body = await c.req.json<{ defaultPermissions: string[] }>();

    if (!Array.isArray(body.defaultPermissions)) {
        return c.json({ success: false, error: 'defaultPermissions must be an array of strings' }, 400);
    }

    const updated = await updateRole(id, { defaultPermissions: body.defaultPermissions });
    if (!updated) {
        return c.json({ success: false, error: 'Role not found' }, 404);
    }

    // Invalidate RBAC cache so permission changes take effect immediately
    invalidateRbacCache();
    log.info('Role permissions updated', { roleId: id, permissions: body.defaultPermissions.length });

    return c.json({ success: true, role: updated });
});

// ============================================================================
// Keycloak Role Mapping
// ============================================================================

/** GET /admin/rbac/keycloak/mapping — Current Keycloak→platform role mapping */
router.get('/keycloak/mapping', (c) => {
    const mapping = getKeycloakMapping();
    return c.json({
        success: true,
        mapping,
        entries: Object.entries(mapping).map(([keycloakRole, platformRole]) => ({
            keycloakRole,
            platformRole,
        })),
    });
});

/** PUT /admin/rbac/keycloak/mapping — Update Keycloak→platform role mapping */
router.put('/keycloak/mapping', async (c) => {
    const body = await c.req.json<{ mapping: Record<string, string> }>();

    if (!body.mapping || typeof body.mapping !== 'object') {
        return c.json({ success: false, error: 'mapping must be an object { keycloakRole: platformRole }' }, 400);
    }

    // Validate platform roles exist
    const validRoles = ['admin', 'analyst', 'developer', 'auditor', 'viewer'];
    for (const [kcRole, platformRole] of Object.entries(body.mapping)) {
        if (!validRoles.includes(platformRole)) {
            return c.json({
                success: false,
                error: `Invalid platform role "${platformRole}" for Keycloak role "${kcRole}". Valid roles: ${validRoles.join(', ')}`,
            }, 400);
        }
    }

    setKeycloakMapping(body.mapping);
    await saveKeycloakMappingToRedis();

    log.info('Keycloak mapping updated', { entries: Object.keys(body.mapping).length });

    return c.json({
        success: true,
        mapping: getKeycloakMapping(),
    });
});

/** POST /admin/rbac/keycloak/sync — Sync roles from Keycloak (check availability) */
router.post('/keycloak/sync', async (c) => {
    try {
        const { keycloak } = await import('../../services/keycloak');
        // Reset cached availability so we do a fresh connectivity check
        keycloak.resetAvailability();
        const available = await keycloak.isAvailable();

        if (!available) {
            return c.json({
                success: false,
                error: 'Keycloak is not available. Check KEYCLOAK_URL environment variable.',
            }, 503);
        }

        return c.json({
            success: true,
            message: 'Keycloak is available. Role mapping is configured.',
            keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8443',
            realm: process.env.KEYCLOAK_REALM || 'rinjani',
            currentMapping: getKeycloakMapping(),
        });
    } catch (err) {
        return c.json({
            success: false,
            error: `Keycloak sync failed: ${(err as Error).message}`,
        }, 500);
    }
});

// ============================================================================
// RBAC Overview / Summary
// ============================================================================

/** GET /admin/rbac/summary — Quick overview of RBAC configuration */
router.get('/summary', async (c) => {
    const roles = await listRoles();
    const permModules = await listPermissionModules();
    const policies = getRoutePolicies();
    const mapping = getKeycloakMapping();

    // Check Keycloak availability
    let keycloakAvailable = false;
    try {
        const { keycloak } = await import('../../services/keycloak');
        // Reset cache so dashboard always shows current connectivity
        keycloak.resetAvailability();
        keycloakAvailable = await keycloak.isAvailable();
    } catch { /* ignore */ }

    // Check Vault availability
    let vaultAvailable = false;
    try {
        const { secrets } = await import('../../services/vault');
        vaultAvailable = await secrets.isAvailable();
    } catch { /* ignore */ }

    return c.json({
        success: true,
        summary: {
            totalRoles: roles.length,
            systemRoles: roles.filter(r => r.isSystem).length,
            customRoles: roles.filter(r => !r.isSystem).length,
            permissionModules: permModules.length,
            totalPermissions: permModules.reduce((sum, m) => sum + (m.permissions?.length || 0), 0),
            routePolicies: policies.length,
            keycloakMappings: Object.keys(mapping).length,
            keycloakAvailable,
            vaultAvailable,
        },
    });
});

export default router;
