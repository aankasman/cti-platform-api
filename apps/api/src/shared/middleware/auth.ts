/**
 * Authentication Middleware
 * 
 * Provides API key and JWT authentication for V3 API.
 * Supports multiple authentication methods:
 * - Bearer token (JWT)
 * - X-API-Key header
 * - Query parameter ?api_key=xxx
 */

import type { Context, Next } from 'hono';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { createHmac } from 'crypto';

// ============================================================================
// Configuration
// ============================================================================

// Parse API_KEYS from environment: format "key1:role,key2:role"
function parseApiKeys(): Map<string, { name: string; role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer' }> {
    const keys = new Map<string, { name: string; role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer' }>();

    // Always include dev key for backwards compatibility
    keys.set('cti-dev-key-2026', { name: 'Development Key', role: 'admin' });

    const envKeys = process.env.API_KEYS;
    if (envKeys) {
        envKeys.split(',').forEach((entry, index) => {
            const [key, role] = entry.trim().split(':');
            if (key && role && ['admin', 'analyst', 'developer', 'auditor', 'viewer'].includes(role)) {
                keys.set(key, {
                    name: `API Key ${index + 1}`,
                    role: role as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer'
                });
            }
        });
    }

    return keys;
}

const API_KEYS = parseApiKeys();

const JWT_SECRET = process.env.JWT_SECRET || 'cti-jwt-secret-change-in-production';

// ============================================================================
// Types
// ============================================================================

export interface AuthUser {
    id: string;
    name: string;
    role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
    permissions: string[];
    method: 'api_key' | 'jwt' | 'keycloak';
    tenantId?: string;
    tenantRole?: string;
}

declare module 'hono' {
    interface ContextVariableMap {
        user: AuthUser;
    }
}

// ============================================================================
// JWT Helpers
// ============================================================================

interface JWTPayload {
    sub: string;
    name: string;
    role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
    iat: number;
    exp: number;
    tenantId?: string;
    tenantRole?: string;
}

export function createJWT(payload: Omit<JWTPayload, 'iat'>): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);

    const fullPayload: JWTPayload = { ...payload, iat: now };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');

    const signature = createHmac('sha256', JWT_SECRET)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64url');

    return `${headerB64}.${payloadB64}.${signature}`;
}

export function verifyJWT(token: string): JWTPayload | null {
    try {
        const [headerB64, payloadB64, signature] = token.split('.');
        if (!headerB64 || !payloadB64 || !signature) return null;

        const expectedSignature = createHmac('sha256', JWT_SECRET)
            .update(`${headerB64}.${payloadB64}`)
            .digest('base64url');

        if (signature !== expectedSignature) return null;

        const payload: JWTPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return null;

        return payload;
    } catch {
        return null;
    }
}

// ============================================================================
// Authentication Middleware
// ============================================================================

export async function optionalAuth(c: Context, next: Next) {
    const authHeader = c.req.header('Authorization');
    const apiKey = c.req.header('X-API-Key') || c.req.query('api_key');

    if (apiKey && API_KEYS.has(apiKey)) {
        const keyInfo = API_KEYS.get(apiKey)!;
        c.set('user', {
            id: `key:${apiKey.substring(0, 8)}`,
            name: keyInfo.name,
            role: keyInfo.role,
            permissions: [],
            method: 'api_key',
        });
    } else if (authHeader?.startsWith('Bearer ')) {
        const payload = verifyJWT(authHeader.slice(7));
        if (payload) {
            c.set('user', {
                id: payload.sub,
                name: payload.name,
                role: payload.role,
                permissions: [],
                method: 'jwt',
                tenantId: payload.tenantId,
                tenantRole: payload.tenantRole,
            });
        }
    }

    // Eagerly resolve permissions from DB if user is authenticated
    const user = c.get('user');
    if (user && user.permissions.length === 0) {
        try {
            const { resolvePermissions } = await import('../../services/rbacService');
            user.permissions = await resolvePermissions(user.role);
            c.set('user', user);
        } catch {
            // RBAC service unavailable — use empty permissions (role checks still work)
        }
    }

    await next();
}

export async function requireAuth(c: Context, next: Next) {
    await optionalAuth(c, async () => { });

    if (!c.get('user')) {
        throw new HTTPException(401, {
            message: 'Authentication required. Provide X-API-Key header or Bearer token.',
        });
    }

    await next();
}

export function requireRole(...roles: ('admin' | 'analyst' | 'developer' | 'auditor' | 'viewer')[]) {
    return async (c: Context, next: Next) => {
        const user = c.get('user');
        if (!user) throw new HTTPException(401, { message: 'Authentication required' });
        if (!roles.includes(user.role)) {
            throw new HTTPException(403, { message: `Access denied. Required role: ${roles.join(' or ')}` });
        }
        await next();
    };
}

/**
 * Permission-based access control middleware.
 * Checks if the authenticated user has any of the required permissions.
 * Supports wildcard permissions ('*', 'iocs:*').
 *
 * Usage:
 *   router.get('/iocs', requireAuth, requirePermission('iocs:read'), handler)
 *   router.post('/iocs', requireAuth, requirePermission('iocs:write'), handler)
 */
export function requirePermission(...permissions: string[]) {
    return async (c: Context, next: Next) => {
        const user = c.get('user');
        if (!user) throw new HTTPException(401, { message: 'Authentication required' });

        try {
            const { hasAnyPermission, resolvePermissions } = await import('../../services/rbacService');

            // Ensure permissions are resolved
            let userPerms = user.permissions;
            if (!userPerms || userPerms.length === 0) {
                userPerms = await resolvePermissions(user.role);
                user.permissions = userPerms;
                c.set('user', user);
            }

            if (!hasAnyPermission(userPerms, permissions)) {
                throw new HTTPException(403, {
                    message: `Access denied. Required permission: ${permissions.join(' or ')}`,
                });
            }
        } catch (err) {
            if (err instanceof HTTPException) throw err;
            // RBAC service failure — fall back to role-based check (admin always passes)
            if (user.role !== 'admin') {
                throw new HTTPException(403, {
                    message: 'Permission check unavailable. Contact administrator.',
                });
            }
        }

        await next();
    };
}

// Legacy export for backward compatibility
export const authMiddleware = requireAuth;
export default authMiddleware;

// ============================================================================
// Auth API Routes
// ============================================================================

export const authRouter = new Hono();

authRouter.post('/login', async (c) => {
    const body = await c.req.json<{ username?: string; password?: string; api_key?: string }>();

    if (body.api_key && API_KEYS.has(body.api_key)) {
        const keyInfo = API_KEYS.get(body.api_key)!;
        const token = createJWT({
            sub: `key:${body.api_key.substring(0, 8)}`,
            name: keyInfo.name,
            role: keyInfo.role,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });
        return c.json({ success: true, token, user: { name: keyInfo.name, role: keyInfo.role }, expiresIn: '24h' });
    }

    if (body.username === 'admin' && body.password === 'admin') {
        const token = createJWT({
            sub: 'user:admin',
            name: 'Administrator',
            role: 'admin',
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });
        return c.json({ success: true, token, user: { name: 'Administrator', role: 'admin' }, expiresIn: '24h' });
    }

    return c.json({ success: false, error: 'Invalid credentials' }, 401);
});

authRouter.get('/verify', requireAuth, (c) => {
    const user = c.get('user');
    return c.json({ success: true, user: { id: user.id, name: user.name, role: user.role, method: user.method } });
});

authRouter.post('/refresh', requireAuth, (c) => {
    const user = c.get('user');
    const token = createJWT({
        sub: user.id,
        name: user.name,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
    });
    return c.json({ success: true, token, expiresIn: '24h' });
});

authRouter.get('/my-tenants', requireAuth, async (c) => {
    const user = c.get('user');
    try {
        const { getUserTenants } = await import('../../services/federation');
        const tenants = await getUserTenants(user.id);
        return c.json({ success: true, data: tenants });
    } catch {
        return c.json({ success: true, data: [] });
    }
});

authRouter.post('/tenant-select', requireAuth, async (c) => {
    const user = c.get('user');
    const { tenantId } = await c.req.json<{ tenantId: string }>();
    if (!tenantId) return c.json({ success: false, error: 'tenantId is required' }, 400);

    try {
        const { getUserTenants } = await import('../../services/federation');
        const memberships = await getUserTenants(user.id);
        const membership = memberships.find(m => m.tenantId === tenantId);
        if (!membership) {
            return c.json({ success: false, error: 'You are not a member of this tenant' }, 403);
        }

        const token = createJWT({
            sub: user.id,
            name: user.name,
            role: user.role,
            tenantId: membership.tenantId,
            tenantRole: membership.tenantRole,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });

        return c.json({
            success: true,
            token,
            tenant: {
                id: membership.tenantId,
                name: membership.tenantName,
                slug: membership.tenantSlug,
                role: membership.tenantRole,
            },
            expiresIn: '24h',
        });
    } catch (err) {
        return c.json({ success: false, error: (err as Error).message }, 500);
    }
});
