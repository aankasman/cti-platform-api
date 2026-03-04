/**
 * Multi-Tenant Federation Service
 *
 * Enables federation between multiple Rinjani instances:
 *   - Tenant isolation with scoped data access (PostgreSQL schemas)
 *   - Cross-tenant intelligence sharing with TLP controls
 *   - Federated search across trusted peers
 *   - Tenant lifecycle management (create, suspend, delete)
 *
 * Uses sql.raw() for dynamic queries to avoid Drizzle version conflicts.
 */

import { db, sql, rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { createLogger } from '../lib/logger';
import { escSql } from '../lib/sanitize';

const log = createLogger('Federation');

// ============================================================================
// Types
// ============================================================================

export interface Tenant {
    id: string;
    name: string;
    slug: string;
    status: 'active' | 'suspended' | 'pending' | 'deleted';
    tier: 'free' | 'pro' | 'enterprise';
    config: TenantConfig;
    createdAt: string;
    updatedAt: string;
}

export interface TenantConfig {
    maxIOCs: number;
    maxCVEs: number;
    maxUsers: number;
    maxFeeds: number;
    enableAI: boolean;
    enableGraphSync: boolean;
    enableVectorSearch: boolean;
    retentionDays: number;
    sharingPolicy: SharingPolicy;
    quotas: TenantQuotas;
}

export interface SharingPolicy {
    defaultTLP: 'white' | 'green' | 'amber' | 'red';
    allowInbound: boolean;
    allowOutbound: boolean;
    trustedPeers: string[];
    blockedPeers: string[];
    autoShareTypes: string[];
    minConfidenceToShare: number;
}

export interface TenantQuotas {
    apiCallsPerHour: number;
    storageGB: number;
    enrichmentsPerDay: number;
    exportPerDay: number;
}

export interface FederationPeer {
    id: string;
    name: string;
    url: string;
    apiKey: string;
    status: 'connected' | 'disconnected' | 'error';
    lastSyncAt: string | null;
    trustLevel: 'full' | 'limited' | 'read-only';
    sharedObjectCount: number;
}

export interface FederatedSearchResult {
    peerId: string;
    peerName: string;
    results: unknown[];
    latencyMs: number;
    error?: string;
}

// ============================================================================
// Tier Defaults
// ============================================================================

const TIER_DEFAULTS: Record<string, TenantConfig> = {
    free: {
        maxIOCs: 50_000, maxCVEs: 10_000, maxUsers: 3, maxFeeds: 5,
        enableAI: false, enableGraphSync: false, enableVectorSearch: false, retentionDays: 30,
        sharingPolicy: {
            defaultTLP: 'green', allowInbound: true, allowOutbound: false,
            trustedPeers: [], blockedPeers: [], autoShareTypes: [], minConfidenceToShare: 80,
        },
        quotas: { apiCallsPerHour: 1000, storageGB: 1, enrichmentsPerDay: 100, exportPerDay: 10 },
    },
    pro: {
        maxIOCs: 500_000, maxCVEs: 100_000, maxUsers: 25, maxFeeds: 20,
        enableAI: true, enableGraphSync: true, enableVectorSearch: true, retentionDays: 180,
        sharingPolicy: {
            defaultTLP: 'amber', allowInbound: true, allowOutbound: true,
            trustedPeers: [], blockedPeers: [], autoShareTypes: ['ip', 'domain'], minConfidenceToShare: 60,
        },
        quotas: { apiCallsPerHour: 10_000, storageGB: 50, enrichmentsPerDay: 1000, exportPerDay: 100 },
    },
    enterprise: {
        maxIOCs: -1, maxCVEs: -1, maxUsers: -1, maxFeeds: -1,
        enableAI: true, enableGraphSync: true, enableVectorSearch: true, retentionDays: 365,
        sharingPolicy: {
            defaultTLP: 'amber', allowInbound: true, allowOutbound: true,
            trustedPeers: [], blockedPeers: [], autoShareTypes: ['ip', 'domain', 'hash', 'url'], minConfidenceToShare: 40,
        },
        quotas: { apiCallsPerHour: -1, storageGB: -1, enrichmentsPerDay: -1, exportPerDay: -1 },
    },
};

// ============================================================================
// Bootstrap (runs DDL once per process, then caches the result)
// ============================================================================

let _tablesReady: Promise<void> | null = null;

function ensureFederationTables(): Promise<void> {
    if (!_tablesReady) {
        _tablesReady = (async () => {
            await db.execute(sql`
                CREATE TABLE IF NOT EXISTS federation_tenants (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    slug        TEXT NOT NULL UNIQUE,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    tier        TEXT NOT NULL DEFAULT 'free',
                    config      JSONB NOT NULL DEFAULT '{}',
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            `);

            await db.execute(sql`
                CREATE TABLE IF NOT EXISTS federation_peers (
                    id                  TEXT PRIMARY KEY,
                    tenant_id           TEXT NOT NULL REFERENCES federation_tenants(id),
                    name                TEXT NOT NULL,
                    url                 TEXT NOT NULL,
                    api_key             TEXT NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'disconnected',
                    trust_level         TEXT NOT NULL DEFAULT 'read-only',
                    last_sync_at        TIMESTAMPTZ,
                    shared_object_count INTEGER DEFAULT 0,
                    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            `);

            await db.execute(sql`
                CREATE TABLE IF NOT EXISTS tenant_user_memberships (
                    id          TEXT PRIMARY KEY,
                    tenant_id   TEXT NOT NULL REFERENCES federation_tenants(id) ON DELETE CASCADE,
                    user_id     TEXT NOT NULL,
                    tenant_role TEXT NOT NULL DEFAULT 'viewer',
                    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(tenant_id, user_id)
                )
            `);
        })();
    }
    return _tablesReady;
}

// ============================================================================
// Tenant Lifecycle
// ============================================================================

export async function createTenant(
    name: string,
    slug: string,
    tier: 'free' | 'pro' | 'enterprise' = 'free',
    configOverrides: Partial<TenantConfig> = {},
): Promise<Tenant> {
    await ensureFederationTables();

    const id = crypto.randomUUID();
    const config = { ...TIER_DEFAULTS[tier], ...configOverrides };

    await db.execute(sql.raw(`
        INSERT INTO federation_tenants (id, name, slug, status, tier, config)
        VALUES ('${id}', '${escSql(name)}', '${escSql(slug)}', 'active', '${tier}',
                '${JSON.stringify(config).replace(/'/g, "''")}'::jsonb)
    `));

    // Create tenant-specific schema for data isolation
    const schemaName = `tenant_${slug.replace(/[^a-z0-9_]/g, '_')}`;
    await db.execute(sql.raw(`CREATE SCHEMA IF NOT EXISTS ${schemaName}`));

    log.info('Tenant created', { id, name, slug, tier });

    return {
        id, name, slug, status: 'active', tier, config,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
}

export async function suspendTenant(tenantId: string): Promise<void> {
    await db.execute(sql.raw(`
        UPDATE federation_tenants SET status = 'suspended', updated_at = NOW()
        WHERE id = '${escSql(tenantId)}'
    `));
    log.warn('Tenant suspended', { tenantId });
}

export async function reactivateTenant(tenantId: string): Promise<void> {
    await db.execute(sql.raw(`
        UPDATE federation_tenants SET status = 'active', updated_at = NOW()
        WHERE id = '${escSql(tenantId)}'
    `));
    log.info('Tenant reactivated', { tenantId });
}

export async function updateTenantConfig(
    tenantId: string,
    updates: { tier?: string; config?: Partial<TenantConfig> },
): Promise<Tenant> {
    await ensureFederationTables();

    const existing = await getTenant(tenantId);
    if (!existing) throw new Error('Tenant not found');

    // Merge config: deep-merge sharingPolicy and quotas sub-objects
    const mergedConfig: TenantConfig = {
        ...existing.config,
        ...(updates.config || {}),
        sharingPolicy: {
            ...existing.config.sharingPolicy,
            ...(updates.config?.sharingPolicy || {}),
        },
        quotas: {
            ...existing.config.quotas,
            ...(updates.config?.quotas || {}),
        },
    };

    const newTier = updates.tier || existing.tier;

    await db.execute(sql.raw(`
        UPDATE federation_tenants
        SET config = '${JSON.stringify(mergedConfig).replace(/'/g, "''")}'::jsonb,
            tier = '${escSql(newTier)}',
            updated_at = NOW()
        WHERE id = '${escSql(tenantId)}'
    `));

    log.info('Tenant config updated', { tenantId, tier: newTier });

    return {
        ...existing,
        tier: newTier as Tenant['tier'],
        config: mergedConfig,
        updatedAt: new Date().toISOString(),
    };
}

export async function getTenant(idOrSlug: string): Promise<Tenant | null> {
    await ensureFederationTables();
    const result = await rawQuery(`
        SELECT id, name, slug, status, tier, config::text, created_at::text, updated_at::text
        FROM federation_tenants
        WHERE id = '${escSql(idOrSlug)}' OR slug = '${escSql(idOrSlug)}'
        LIMIT 1
    `);

    const rows = (Array.isArray(result) ? result : (result as unknown as { rows?: Record<string, unknown>[] }).rows || []) as Record<string, unknown>[];
    if (rows.length === 0) return null;
    const row = rows[0];
    return {
        id: String(row.id), name: String(row.name), slug: String(row.slug),
        status: String(row.status) as Tenant['status'], tier: String(row.tier) as Tenant['tier'],
        config: typeof row.config === 'string' ? JSON.parse(row.config) : row.config as TenantConfig,
        createdAt: String(row.created_at), updatedAt: String(row.updated_at),
    };
}

export async function listTenants(): Promise<Tenant[]> {
    await ensureFederationTables();
    const result = await rawQuery(`
        SELECT id, name, slug, status, tier, config::text, created_at::text, updated_at::text
        FROM federation_tenants
        WHERE status != 'deleted'
        ORDER BY created_at DESC
    `);

    // db.execute returns rows directly as an array (not { rows: [...] })
    const rows = (Array.isArray(result) ? result : result.rows || []) as Record<string, unknown>[];

    return rows.map((row) => ({
        id: String(row.id), name: String(row.name), slug: String(row.slug),
        status: String(row.status) as Tenant['status'], tier: String(row.tier) as Tenant['tier'],
        config: typeof row.config === 'string' ? JSON.parse(row.config as string) : row.config as TenantConfig,
        createdAt: String(row.created_at), updatedAt: String(row.updated_at),
    }));
}

// ============================================================================
// Peering
// ============================================================================

export async function addPeer(
    tenantId: string, name: string, url: string, apiKey: string,
    trustLevel: 'full' | 'limited' | 'read-only' = 'read-only',
): Promise<FederationPeer> {
    await ensureFederationTables();
    const id = crypto.randomUUID();

    await db.execute(sql.raw(`
        INSERT INTO federation_peers (id, tenant_id, name, url, api_key, trust_level, status)
        VALUES ('${id}', '${escSql(tenantId)}', '${escSql(name)}', '${escSql(url)}',
                '${escSql(apiKey)}', '${trustLevel}', 'disconnected')
    `));

    log.info('Federation peer added', { id, tenantId, name, url: url.replace(/\/\/.*@/, '//****@') });

    return {
        id, name, url, apiKey: '••••' + apiKey.slice(-4),
        status: 'disconnected', lastSyncAt: null, trustLevel, sharedObjectCount: 0,
    };
}

export async function listPeers(tenantId: string): Promise<FederationPeer[]> {
    await ensureFederationTables();
    const result = await rawQuery(`
        SELECT id, name, url, api_key, status, trust_level, last_sync_at::text, shared_object_count
        FROM federation_peers WHERE tenant_id = '${escSql(tenantId)}'
        ORDER BY created_at DESC
    `);

    const rows = (Array.isArray(result) ? result : result.rows || []) as Record<string, unknown>[];

    return rows.map((row) => ({
        id: String(row.id), name: String(row.name), url: String(row.url),
        apiKey: '••••' + String(row.api_key || '').slice(-4),
        status: String(row.status) as FederationPeer['status'],
        trustLevel: String(row.trust_level) as FederationPeer['trustLevel'],
        lastSyncAt: row.last_sync_at ? String(row.last_sync_at) : null,
        sharedObjectCount: Number(row.shared_object_count || 0),
    }));
}

export async function testPeerConnection(peerId: string): Promise<{
    reachable: boolean; latencyMs: number; version?: string; error?: string;
}> {
    const result = await rawQuery<{ url: string; api_key: string }>(
        `SELECT url, api_key FROM federation_peers WHERE id = '${escSql(peerId)}' LIMIT 1`
    );

    const rows = (Array.isArray(result) ? result : (result as unknown as { rows?: Record<string, unknown>[] }).rows || []) as Array<{ url: string; api_key: string }>;
    if (rows.length === 0) return { reachable: false, latencyMs: 0, error: 'Peer not found' };

    const { url, api_key } = rows[0];
    const startTime = Date.now();

    try {
        const response = await fetch(`${url}/api/v1`, {
            headers: { Authorization: `Bearer ${api_key}` },
            signal: AbortSignal.timeout(10000),
        });

        const latencyMs = Date.now() - startTime;
        const data = await response.json() as Record<string, unknown>;
        const status = response.ok ? 'connected' : 'error';

        await db.execute(sql.raw(`
            UPDATE federation_peers SET status = '${status}', last_sync_at = NOW(), updated_at = NOW()
            WHERE id = '${escSql(peerId)}'
        `));

        return { reachable: response.ok, latencyMs, version: data?.version as string | undefined, error: response.ok ? undefined : `HTTP ${response.status}` };
    } catch (err) {
        await db.execute(sql.raw(`
            UPDATE federation_peers SET status = 'error', updated_at = NOW() WHERE id = '${escSql(peerId)}'
        `));
        return { reachable: false, latencyMs: Date.now() - startTime, error: (err as Error).message };
    }
}

// ============================================================================
// Federated Search
// ============================================================================

export async function federatedSearch(
    tenantId: string,
    query: string,
    options: { type?: string; limit?: number; timeout?: number } = {},
): Promise<FederatedSearchResult[]> {
    const { type = 'ioc', limit = 50, timeout = 8000 } = options;
    const peers = await listPeers(tenantId);
    const activePeers = peers.filter(p => p.status === 'connected' && p.trustLevel !== 'read-only');
    if (activePeers.length === 0) return [];

    const results = await Promise.allSettled(
        activePeers.map(async (peer): Promise<FederatedSearchResult> => {
            const startTime = Date.now();
            try {
                const response = await fetch(`${peer.url}/api/v1/search`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${peer.apiKey}` },
                    body: JSON.stringify({ query, type, limit }),
                    signal: AbortSignal.timeout(timeout),
                });
                const data = await response.json() as Record<string, unknown>;
                return { peerId: peer.id, peerName: peer.name, results: (data.results || data.data || []) as unknown[], latencyMs: Date.now() - startTime };
            } catch (err) {
                return { peerId: peer.id, peerName: peer.name, results: [], latencyMs: Date.now() - startTime, error: (err as Error).message };
            }
        })
    );

    return results.map(r => r.status === 'fulfilled' ? r.value : { peerId: 'unknown', peerName: 'unknown', results: [], latencyMs: 0, error: 'Promise rejected' });
}

// ============================================================================
// Intelligence Sharing
// ============================================================================

export async function shareIntelligence(
    tenantId: string,
    entityType: 'ioc' | 'cve' | 'actor',
    entityId: string,
    tlp: string = 'green',
): Promise<{ sharedWith: string[]; errors: Array<{ peer: string; error: string }> }> {
    const tenant = await getTenant(tenantId);
    if (!tenant) throw new Error('Tenant not found');

    const policy = tenant.config.sharingPolicy;
    if (!policy.allowOutbound) return { sharedWith: [], errors: [{ peer: '*', error: 'Outbound sharing disabled' }] };

    const tlpOrder = ['white', 'green', 'amber', 'red'];
    if (tlpOrder.indexOf(tlp.toLowerCase()) > tlpOrder.indexOf(policy.defaultTLP)) {
        return { sharedWith: [], errors: [{ peer: '*', error: `TLP ${tlp} exceeds tenant policy (${policy.defaultTLP})` }] };
    }

    const peers = await listPeers(tenantId);
    const eligible = peers.filter(p =>
        p.status === 'connected' && ['full', 'limited'].includes(p.trustLevel) && !policy.blockedPeers.includes(p.id)
    );

    const table = entityType === 'ioc' ? 'iocs' : entityType === 'cve' ? 'vulnerabilities' : 'threat_actors';
    const entityResult = await rawQuery(`SELECT * FROM ${table} WHERE id = '${escSql(entityId)}' LIMIT 1`);
    const entity = (entityResult.rows || [])[0];
    if (!entity) return { sharedWith: [], errors: [{ peer: '*', error: 'Entity not found' }] };

    const sharedWith: string[] = [];
    const errors: Array<{ peer: string; error: string }> = [];

    for (const peer of eligible) {
        try {
            const response = await fetch(`${peer.url}/api/v1/stix/import`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${peer.apiKey}` },
                body: JSON.stringify({ type: 'bundle', id: `bundle--shared-${Date.now()}`, objects: [entity] }),
                signal: AbortSignal.timeout(10000),
            });
            if (response.ok) {
                sharedWith.push(peer.name);
                await db.execute(sql.raw(`UPDATE federation_peers SET shared_object_count = shared_object_count + 1, updated_at = NOW() WHERE id = '${escSql(peer.id)}'`));
            } else {
                errors.push({ peer: peer.name, error: `HTTP ${response.status}` });
            }
        } catch (err) {
            errors.push({ peer: peer.name, error: (err as Error).message });
        }
    }

    log.info('Intelligence shared', { tenantId, entityType, entityId, sharedWith: sharedWith.length, errors: errors.length });
    return { sharedWith, errors };
}

// ============================================================================
// Admin Stats
// ============================================================================

export async function getFederationStats(): Promise<{
    totalTenants: number; activeTenants: number;
    totalPeers: number; activePeers: number; connectedPeers: number; totalSharedObjects: number;
}> {
    await ensureFederationTables();
    const [tenantStats, peerStats] = await Promise.all([
        rawQuery(`
            SELECT count(*)::int as total,
                   count(*) FILTER (WHERE status = 'active')::int as active
            FROM federation_tenants
        `),
        rawQuery(`
            SELECT count(*)::int as total,
                   count(*) FILTER (WHERE status = 'connected')::int as connected,
                   COALESCE(sum(shared_object_count), 0)::int as shared
            FROM federation_peers
        `),
    ]);

    // db.execute returns rows directly as an array (not { rows: [...] })
    const tRows = Array.isArray(tenantStats) ? tenantStats : tenantStats.rows || [];
    const pRows = Array.isArray(peerStats) ? peerStats : peerStats.rows || [];
    const tRow = (tRows[0] || {}) as Record<string, unknown>;
    const pRow = (pRows[0] || {}) as Record<string, unknown>;

    const connectedPeers = Number(pRow.connected || 0);
    return {
        totalTenants: Number(tRow.total || 0), activeTenants: Number(tRow.active || 0),
        totalPeers: Number(pRow.total || 0), connectedPeers, activePeers: connectedPeers,
        totalSharedObjects: Number(pRow.shared || 0),
    };
}

// ============================================================================
// Tenant User Membership
// ============================================================================

export interface TenantMember {
    id: string;
    tenantId: string;
    userId: string;
    userName: string;
    userEmail: string;
    tenantRole: string;
    isActive: boolean;
    joinedAt: string;
}

export interface InviteResult {
    member: TenantMember;
    credentials: {
        apiToken: string;
        temporaryPassword?: string;
        keycloakSynced: boolean;
    };
    isNewUser: boolean;
}

/** Best-effort Keycloak group sync for a member. */
async function syncMemberToKeycloak(
    email: string, name: string, tenantSlug: string, tempPassword?: string,
): Promise<{ kcSynced: boolean; tempPw?: string }> {
    try {
        const { keycloak } = await import('./keycloak');
        const available = await keycloak.isAvailable();
        log.info('KC sync: availability check', { available });
        if (!available) return { kcSynced: false };

        const pw = tempPassword || crypto.randomUUID().slice(0, 12);
        const kcUserId = await keycloak.createKeycloakUser(email, name, pw);
        log.info('KC sync: createUser result', { email, kcUserId });
        if (!kcUserId) return { kcSynced: false };

        const groupId = await keycloak.ensureTenantGroup(tenantSlug);
        log.info('KC sync: ensureGroup result', { tenantSlug, groupId });
        if (groupId) {
            const added = await keycloak.addUserToGroup(kcUserId, groupId);
            log.info('KC sync: addUserToGroup result', { kcUserId, groupId, added });
        }

        return { kcSynced: true, tempPw: pw };
    } catch (err) {
        log.error('KC sync: unexpected error', { error: (err as Error).message, stack: (err as Error).stack });
        return { kcSynced: false };
    }
}

export async function addTenantMember(
    tenantId: string,
    userId: string,
    tenantRole: string = 'viewer',
): Promise<TenantMember> {
    await ensureFederationTables();
    const id = crypto.randomUUID();

    await db.execute(sql.raw(`
        INSERT INTO tenant_user_memberships (id, tenant_id, user_id, tenant_role)
        VALUES ('${id}', '${escSql(tenantId)}', '${escSql(userId)}', '${escSql(tenantRole)}')
    `));

    // Fetch joined data to return
    const result = await rawQuery(`
        SELECT m.id, m.tenant_id, m.user_id, m.tenant_role, m.joined_at::text,
               u.name as user_name, u.email as user_email, u.is_active
        FROM tenant_user_memberships m
        JOIN users u ON u.id::text = m.user_id
        WHERE m.id = '${escSql(id)}'
        LIMIT 1
    `);
    const rows = Array.isArray(result) ? result : result.rows || [];
    const row = rows[0] as Record<string, unknown>;

    // Best-effort Keycloak sync
    const email = String(row?.user_email || '');
    const name = String(row?.user_name || '');
    if (email) {
        const tenant = await getTenant(tenantId);
        if (tenant) syncMemberToKeycloak(email, name, tenant.slug).catch(() => { });
    }

    log.info('Tenant member added', { tenantId, userId, tenantRole });

    return {
        id, tenantId, userId,
        userName: name,
        userEmail: email,
        tenantRole,
        isActive: Boolean(row?.is_active),
        joinedAt: String(row?.joined_at || new Date().toISOString()),
    };
}

export async function removeTenantMember(tenantId: string, userId: string): Promise<boolean> {
    await ensureFederationTables();

    // Get user email for KC sync before deleting
    const members = await listTenantMembers(tenantId);
    const member = members.find(m => m.userId === userId);

    await db.execute(sql.raw(`
        DELETE FROM tenant_user_memberships
        WHERE tenant_id = '${escSql(tenantId)}' AND user_id = '${escSql(userId)}'
    `));

    // Best-effort Keycloak sync: remove from group
    if (member?.userEmail) {
        try {
            const { keycloak } = await import('./keycloak');
            if (await keycloak.isAvailable()) {
                const tenant = await getTenant(tenantId);
                const kcUser = await keycloak.findUserByEmail(member.userEmail);
                if (kcUser && tenant) {
                    const groupId = await keycloak.ensureTenantGroup(tenant.slug);
                    if (groupId) await keycloak.removeUserFromGroup(kcUser.id, groupId);
                }
            }
        } catch { /* best effort */ }
    }

    log.info('Tenant member removed', { tenantId, userId });
    return true;
}

/**
 * Invite a user to a tenant. Creates platform user if needed,
 * adds membership, and syncs to Keycloak.
 */
export async function inviteTenantMember(
    tenantId: string,
    email: string,
    name: string,
    tenantRole: string = 'viewer',
): Promise<InviteResult> {
    const { createUser, getUserByEmail } = await import('./userService');

    // Check if user exists
    let isNewUser = false;
    let user = await getUserByEmail(email);
    if (!user) {
        user = await createUser({ email, name, role: tenantRole });
        isNewUser = true;
    }

    // Add to tenant
    const member = await addTenantMember(tenantId, user.id, tenantRole);

    // Keycloak sync with temp password
    const tenant = await getTenant(tenantId);
    const tempPassword = crypto.randomUUID().slice(0, 12);
    const kcResult = tenant
        ? await syncMemberToKeycloak(email, name, tenant.slug, tempPassword)
        : { kcSynced: false };

    return {
        member,
        credentials: {
            apiToken: user.apiToken || '',
            temporaryPassword: kcResult.kcSynced ? kcResult.tempPw : undefined,
            keycloakSynced: kcResult.kcSynced,
        },
        isNewUser,
    };
}

export async function listTenantMembers(tenantId: string): Promise<TenantMember[]> {
    await ensureFederationTables();
    const result = await rawQuery(`
        SELECT m.id, m.tenant_id, m.user_id, m.tenant_role, m.joined_at::text,
               u.name as user_name, u.email as user_email, u.is_active
        FROM tenant_user_memberships m
        JOIN users u ON u.id::text = m.user_id
        WHERE m.tenant_id = '${escSql(tenantId)}'
        ORDER BY m.joined_at ASC
    `);
    const rows = (Array.isArray(result) ? result : result.rows || []) as Record<string, unknown>[];

    return rows.map((row) => ({
        id: String(row.id),
        tenantId: String(row.tenant_id),
        userId: String(row.user_id),
        userName: String(row.user_name || ''),
        userEmail: String(row.user_email || ''),
        tenantRole: String(row.tenant_role),
        isActive: Boolean(row.is_active),
        joinedAt: String(row.joined_at),
    }));
}

export async function updateMemberRole(
    tenantId: string,
    userId: string,
    newRole: string,
): Promise<boolean> {
    await ensureFederationTables();
    await db.execute(sql.raw(`
        UPDATE tenant_user_memberships
        SET tenant_role = '${escSql(newRole)}'
        WHERE tenant_id = '${escSql(tenantId)}' AND user_id = '${escSql(userId)}'
    `));
    log.info('Tenant member role updated', { tenantId, userId, newRole });
    return true;
}

export async function getUserTenants(userId: string): Promise<Array<{
    tenantId: string; tenantName: string; tenantSlug: string;
    tier: string; tenantRole: string; joinedAt: string;
}>> {
    await ensureFederationTables();
    const result = await rawQuery(`
        SELECT m.tenant_id, m.tenant_role, m.joined_at::text,
               t.name as tenant_name, t.slug as tenant_slug, t.tier
        FROM tenant_user_memberships m
        JOIN federation_tenants t ON t.id = m.tenant_id
        WHERE m.user_id = '${escSql(userId)}' AND t.status = 'active'
        ORDER BY m.joined_at ASC
    `);
    const rows = (Array.isArray(result) ? result : result.rows || []) as Record<string, unknown>[];

    return rows.map((row) => ({
        tenantId: String(row.tenant_id),
        tenantName: String(row.tenant_name),
        tenantSlug: String(row.tenant_slug),
        tier: String(row.tier),
        tenantRole: String(row.tenant_role),
        joinedAt: String(row.joined_at),
    }));
}

// ============================================================================
// Helpers
// ============================================================================

export function resolveTenantId(headers: Record<string, string>): string | null {
    return headers['x-tenant-id'] || null;
}

export function tenantSchema(tenantSlug: string): string {
    return `tenant_${tenantSlug.replace(/[^a-z0-9_]/g, '_')}`;
}
