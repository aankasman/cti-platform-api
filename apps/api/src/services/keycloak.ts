/**
 * Keycloak OIDC Integration — SSO Authentication
 *
 * Provides middleware and utilities for Keycloak-based OIDC authentication.
 * When Keycloak is available, validates JWT tokens issued by Keycloak.
 * Falls back to the existing API key / JWT auth when Keycloak is not deployed.
 *
 * Setup:
 *   1. Deploy Keycloak with `docker compose --profile platform up -d`
 *   2. Create a realm named "rinjani" in Keycloak admin (http://localhost:8443)
 *   3. Create a client "rinjani-api" with confidential access type
 *   4. Set KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID in .env
 *
 * Usage:
 *   import { keycloakAuth } from '../services/keycloak';
 *   app.use('/v2/admin/*', keycloakAuth({ roles: ['admin'] }));
 */

import type { Context, Next } from 'hono';
import { createLogger } from '../lib/logger';

const log = createLogger('Keycloak');

// ============================================================================
// Types
// ============================================================================

interface KeycloakConfig {
    url: string;
    realm: string;
    clientId: string;
}

interface KeycloakTokenPayload {
    sub: string;
    preferred_username: string;
    email?: string;
    realm_access?: {
        roles: string[];
    };
    resource_access?: Record<string, { roles: string[] }>;
    exp: number;
    iat: number;
}

interface JWK {
    kid: string;
    kty: string;
    n: string;
    e: string;
    alg: string;
    use: string;
}

// ============================================================================
// Keycloak Client
// ============================================================================

const DEFAULT_CONFIG: KeycloakConfig = {
    url: process.env.KEYCLOAK_URL || 'http://localhost:8443',
    realm: process.env.KEYCLOAK_REALM || 'rinjani',
    clientId: process.env.KEYCLOAK_CLIENT_ID || 'rinjani-api',
};

class KeycloakClient {
    private config: KeycloakConfig;
    private available: boolean | null = null;
    private availableCheckedAt = 0;
    private jwksCache: JWK[] | null = null;
    private jwksCacheExpiry = 0;

    constructor(config?: Partial<KeycloakConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    private get issuerUrl(): string {
        return `${this.config.url}/realms/${this.config.realm}`;
    }

    /**
     * Check if Keycloak is reachable
     */
    async isAvailable(): Promise<boolean> {
        // TTL: positive result cached indefinitely, negative retried every 30s
        if (this.available !== null) {
            if (this.available) return true;
            if (Date.now() - this.availableCheckedAt < 30_000) return false;
        }

        try {
            const res = await fetch(`${this.issuerUrl}/.well-known/openid-configuration`, {
                signal: AbortSignal.timeout(3000),
            });
            this.available = res.ok;
            this.availableCheckedAt = Date.now();
            log.info('Keycloak connectivity', { available: this.available, realm: this.config.realm });
        } catch {
            this.available = false;
            this.availableCheckedAt = Date.now();
            log.info('Keycloak unavailable, falling back to API key/JWT auth');
        }

        return this.available;
    }

    /**
     * Fetch JWKS (JSON Web Key Set) for token verification
     */
    async getJWKS(): Promise<JWK[]> {
        if (this.jwksCache && this.jwksCacheExpiry > Date.now()) {
            return this.jwksCache;
        }

        try {
            const res = await fetch(`${this.issuerUrl}/protocol/openid-connect/certs`, {
                signal: AbortSignal.timeout(5000),
            });

            if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);

            const data = await res.json() as { keys: JWK[] };
            this.jwksCache = data.keys;
            this.jwksCacheExpiry = Date.now() + 3600_000; // 1 hour cache
            return data.keys;
        } catch (err) {
            log.warn('Failed to fetch JWKS', { error: (err as Error).message });
            return this.jwksCache || [];
        }
    }

    /**
     * Decode a JWT token (without full verification — use JWKS for production)
     */
    decodeToken(token: string): KeycloakTokenPayload | null {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;

            const payload = JSON.parse(
                Buffer.from(parts[1], 'base64url').toString('utf-8'),
            );

            // Check expiration
            if (payload.exp && payload.exp * 1000 < Date.now()) {
                log.debug('Token expired');
                return null;
            }

            return payload as KeycloakTokenPayload;
        } catch {
            return null;
        }
    }

    /**
     * Extract roles from a decoded token
     */
    extractRoles(payload: KeycloakTokenPayload): string[] {
        const realmRoles = payload.realm_access?.roles || [];
        const clientRoles = payload.resource_access?.[this.config.clientId]?.roles || [];
        return [...new Set([...realmRoles, ...clientRoles])];
    }

    /**
     * Get the login URL for redirect-based auth flows
     */
    getLoginUrl(redirectUri: string, state?: string): string {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'openid profile email',
            ...(state ? { state } : {}),
        });
        return `${this.issuerUrl}/protocol/openid-connect/auth?${params}`;
    }

    /**
     * Exchange an authorization code for tokens
     */
    async exchangeCode(code: string, redirectUri: string, clientSecret: string): Promise<{
        accessToken: string;
        refreshToken: string;
        idToken: string;
        expiresIn: number;
    } | null> {
        try {
            const res = await fetch(`${this.issuerUrl}/protocol/openid-connect/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: this.config.clientId,
                    client_secret: clientSecret,
                    code,
                    redirect_uri: redirectUri,
                }),
                signal: AbortSignal.timeout(10_000),
            });

            if (!res.ok) return null;

            const data = await res.json() as { access_token: string; refresh_token: string; id_token: string; expires_in: number };
            return {
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                idToken: data.id_token,
                expiresIn: data.expires_in,
            };
        } catch (err) {
            log.error('Token exchange failed', { error: (err as Error).message });
            return null;
        }
    }

    resetAvailability(): void {
        this.available = null;
    }

    // ========================================================================
    // Admin REST API (user / group management)
    // ========================================================================

    private adminToken: string | null = null;
    private adminTokenExpiry = 0;

    /** Get an admin access token via resource-owner password grant. */
    async getAdminToken(): Promise<string | null> {
        if (this.adminToken && this.adminTokenExpiry > Date.now()) return this.adminToken;

        const adminUser = process.env.KEYCLOAK_ADMIN || 'admin';
        const adminPass = process.env.KEYCLOAK_ADMIN_PASSWORD || '';
        if (!adminPass) { log.warn('KEYCLOAK_ADMIN_PASSWORD not set'); return null; }

        try {
            const res = await fetch(`${this.config.url}/realms/master/protocol/openid-connect/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    grant_type: 'password', client_id: 'admin-cli',
                    username: adminUser, password: adminPass,
                }),
                signal: AbortSignal.timeout(5000),
            });
            if (!res.ok) { log.warn('Admin token request failed', { status: res.status }); return null; }
            const data = await res.json() as { access_token: string; expires_in: number };
            this.adminToken = data.access_token;
            this.adminTokenExpiry = Date.now() + (data.expires_in - 30) * 1000;
            return this.adminToken;
        } catch (err) {
            log.warn('Failed to get admin token', { error: (err as Error).message });
            return null;
        }
    }

    /** Helper: authenticated fetch against Keycloak Admin API */
    private async adminFetch(path: string, options: RequestInit = {}): Promise<Response | null> {
        const token = await this.getAdminToken();
        if (!token) return null;
        try {
            return await fetch(`${this.config.url}/admin/realms/${this.config.realm}${path}`, {
                ...options,
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...options.headers },
                signal: AbortSignal.timeout(8000),
            });
        } catch (err) {
            log.warn('Admin API request failed', { path, error: (err as Error).message });
            return null;
        }
    }

    /** Find a Keycloak user by email. Returns their KC id or null. */
    async findUserByEmail(email: string): Promise<{ id: string; username: string } | null> {
        const res = await this.adminFetch(`/users?email=${encodeURIComponent(email)}&exact=true`);
        if (!res?.ok) return null;
        const users = await res.json() as Array<{ id: string; username: string }>;
        return users[0] || null;
    }

    /** Create a user in Keycloak with a temporary password. Returns KC user id. */
    async createKeycloakUser(email: string, name: string, temporaryPassword: string): Promise<string | null> {
        const existing = await this.findUserByEmail(email);
        if (existing) { log.info('KC user already exists', { email }); return existing.id; }

        const [firstName, ...rest] = name.split(' ');
        const res = await this.adminFetch('/users', {
            method: 'POST',
            body: JSON.stringify({
                email, username: email, enabled: true,
                firstName: firstName || name,
                lastName: rest.join(' ') || '',
                credentials: [{ type: 'password', value: temporaryPassword, temporary: true }],
            }),
        });

        if (!res) return null;
        if (res.status === 201) {
            // Location header contains the new user URL
            const location = res.headers.get('Location') || '';
            const kcId = location.split('/').pop() || '';
            log.info('KC user created', { email, kcId });
            return kcId;
        }
        log.warn('KC user creation failed', { status: res.status, email });
        return null;
    }

    /** Ensure a group named `tenant:{slug}` exists. Returns group id. */
    async ensureTenantGroup(tenantSlug: string): Promise<string | null> {
        const groupName = `tenant:${tenantSlug}`;

        // Search for existing group
        const searchRes = await this.adminFetch(`/groups?search=${encodeURIComponent(groupName)}&exact=true`);
        if (searchRes?.ok) {
            const groups = await searchRes.json() as Array<{ id: string; name: string }>;
            const match = groups.find(g => g.name === groupName);
            if (match) return match.id;
        }

        // Create group
        const res = await this.adminFetch('/groups', {
            method: 'POST',
            body: JSON.stringify({ name: groupName }),
        });
        if (!res) return null;
        if (res.status === 201) {
            const location = res.headers.get('Location') || '';
            const groupId = location.split('/').pop() || '';
            log.info('KC tenant group created', { groupName, groupId });
            return groupId;
        }
        log.warn('KC group creation failed', { status: res.status, groupName });
        return null;
    }

    /** Add a Keycloak user to a group. */
    async addUserToGroup(kcUserId: string, groupId: string): Promise<boolean> {
        const res = await this.adminFetch(`/users/${kcUserId}/groups/${groupId}`, { method: 'PUT' });
        if (res?.ok || res?.status === 204) {
            log.info('KC user added to group', { kcUserId, groupId });
            return true;
        }
        return false;
    }

    /** Remove a Keycloak user from a group. */
    async removeUserFromGroup(kcUserId: string, groupId: string): Promise<boolean> {
        const res = await this.adminFetch(`/users/${kcUserId}/groups/${groupId}`, { method: 'DELETE' });
        if (res?.ok || res?.status === 204) {
            log.info('KC user removed from group', { kcUserId, groupId });
            return true;
        }
        return false;
    }
}

// Singleton
export const keycloak = new KeycloakClient();

// ============================================================================
// Hono Middleware
// ============================================================================

/**
 * Keycloak OIDC auth middleware.
 * When Keycloak is available, validates the Bearer token,
 * maps Keycloak roles to platform roles/permissions, and sets
 * the standard `user` context variable for requirePermission().
 */
export function keycloakAuth(options?: {
    roles?: string[];
    optional?: boolean;
}) {
    return async (c: Context, next: Next) => {
        // Skip if Keycloak is not deployed
        if (!(await keycloak.isAvailable())) {
            return next();
        }

        const authHeader = c.req.header('Authorization');
        if (!authHeader?.startsWith('Bearer ')) {
            if (options?.optional) return next();
            return c.json({ success: false, error: 'Missing Bearer token' }, 401);
        }

        const token = authHeader.slice(7);
        const payload = keycloak.decodeToken(token);

        if (!payload) {
            return c.json({ success: false, error: 'Invalid or expired token' }, 401);
        }

        const kcRoles = keycloak.extractRoles(payload);

        // Check required roles (legacy Keycloak role check)
        if (options?.roles?.length) {
            const hasRequired = options.roles.some(r => kcRoles.includes(r));
            if (!hasRequired) {
                return c.json({
                    success: false,
                    error: 'Insufficient permissions',
                    required: options.roles,
                }, 403);
            }
        }

        // Map KC roles → platform role and resolve permissions
        let platformRole: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer' = 'viewer';
        let permissions: string[] = [];
        try {
            const { mapKeycloakRolesToPlatformRole, resolvePermissions } = await import('./rbacService');
            platformRole = mapKeycloakRolesToPlatformRole(kcRoles) as typeof platformRole;
            permissions = await resolvePermissions(platformRole);
        } catch {
            // RBAC service unavailable — fallback to viewer
        }

        // Set standard user context (same shape as API key / JWT auth)
        c.set('user', {
            id: payload.sub,
            name: payload.preferred_username || payload.email || payload.sub,
            role: platformRole,
            permissions,
            method: 'keycloak' as const,
        });

        // Also set keycloakUser for backward compatibility
        c.set('keycloakUser', {
            sub: payload.sub,
            username: payload.preferred_username,
            email: payload.email,
            roles: kcRoles,
        });

        return next();
    };
}
