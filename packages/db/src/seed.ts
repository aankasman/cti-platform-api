/**
 * Database Seed Script
 * 
 * Populates the database with sample data for development/testing.
 * 
 * Run with: npx tsx packages/db/src/seed.ts
 */

import { db } from './index';
import { iocs, vulnerabilities, threatActors, pulses, users, roles, permissionModules, auditLogs } from './schema';
import { randomUUID, randomBytes } from 'crypto';

const IOC_TYPES = ['ip', 'domain', 'url', 'hash-md5', 'hash-sha256', 'email'];
const SOURCES = ['AlienVault_OTX', 'MISP', 'ThreatConnect', 'Manual'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const THREAT_TYPES = ['malware', 'phishing', 'c2', 'spam', 'apt', null];

function randomItem<T>(array: T[]): T {
    return array[Math.floor(Math.random() * array.length)];
}

function randomIP(): string {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function randomDomain(): string {
    const domains = ['malware', 'phishing', 'bad', 'evil', 'suspicious'];
    const tlds = ['com', 'net', 'org', 'io', 'xyz'];
    return `${randomItem(domains)}-${Math.random().toString(36).substring(7)}.${randomItem(tlds)}`;
}

function randomHash(): string {
    return [...Array(64)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

/** Generate a secure API token: rjn_<32 random hex chars> */
function generateApiToken(): string {
    return `rjn_${randomBytes(16).toString('hex')}`;
}

// ============================================================================
// Seed Roles (replaces hardcoded ROLE_DEFINITIONS)
// ============================================================================

async function seedRoles() {
    console.log('Seeding roles...');

    const defaultRoles = [
        {
            id: 'admin',
            name: 'Administrator',
            description: 'Full system access — manage users, settings, feeds, and all platform operations.',
            defaultPermissions: ['*'],
            isSystem: true,
        },
        {
            id: 'analyst',
            name: 'Security Analyst',
            description: 'View and edit threat data, run enrichments, access strategic reports.',
            defaultPermissions: [
                'iocs:read', 'iocs:write', 'feeds:read', 'enrichment:execute',
                'reports:read', 'search:execute', 'export:execute', 'alerts:read',
            ],
            isSystem: true,
        },
        {
            id: 'developer',
            name: 'Developer',
            description: 'API access, webhook management, and integration development.',
            defaultPermissions: [
                'iocs:read', 'feeds:read', 'api-keys:read', 'api-keys:generate',
                'webhooks:read', 'webhooks:write', 'search:execute',
            ],
            isSystem: true,
        },
        {
            id: 'auditor',
            name: 'Auditor',
            description: 'Read-only access to audit logs, system activity, and compliance data.',
            defaultPermissions: [
                'audit:read', 'iocs:read', 'feeds:read', 'reports:read',
                'system:read', 'users:read',
            ],
            isSystem: true,
        },
        {
            id: 'viewer',
            name: 'Viewer',
            description: 'Read-only access to dashboards and threat intelligence.',
            defaultPermissions: [
                'iocs:read', 'feeds:read', 'reports:read', 'search:execute',
            ],
            isSystem: true,
        },
    ];

    for (const role of defaultRoles) {
        await db.insert(roles).values({
            ...role,
            createdAt: new Date(),
            updatedAt: new Date(),
        }).onConflictDoNothing();
    }

    console.log(`✓ Seeded ${defaultRoles.length} roles`);
}

// ============================================================================
// Seed Permission Modules (replaces hardcoded PERMISSION_MODULES)
// ============================================================================

async function seedPermissionModules() {
    console.log('Seeding permission modules...');

    const modules = [
        {
            id: 'api-keys',
            name: 'API Key Management',
            icon: 'vpn_key',
            permissions: [
                { id: 'api-keys:generate', name: 'Generate New Keys', description: 'Create persistent API tokens for external integrations.' },
                { id: 'api-keys:revoke', name: 'Revoke Keys', description: 'Force expire existing active tokens.' },
                { id: 'api-keys:read', name: 'View Usage Analytics', description: 'Access to API call volume and latency dashboards.' },
            ],
            isSystem: true,
        },
        {
            id: 'threat-intel',
            name: 'Threat Intelligence Access',
            icon: 'radar',
            permissions: [
                { id: 'iocs:read', name: 'Tactical Feeds (IOCs)', description: 'Read access to raw indicators of compromise (IPs, Hashes).' },
                { id: 'iocs:write', name: 'Edit IOCs', description: 'Create, update, and delete indicators of compromise.' },
                { id: 'reports:read', name: 'Strategic Reports', description: 'Access to high-level PDF reports and campaign analysis.' },
                { id: 'enrichment:execute', name: 'Run Enrichments', description: 'Trigger IOC enrichment via VirusTotal, AbuseIPDB, etc.' },
            ],
            isSystem: true,
        },
        {
            id: 'feeds',
            name: 'Feed Management',
            icon: 'rss_feed',
            permissions: [
                { id: 'feeds:read', name: 'View Feed Status', description: 'Monitor feed health and sync history.' },
                { id: 'feeds:write', name: 'Configure Feeds', description: 'Edit cron schedules and enable/disable feeds.' },
                { id: 'feeds:trigger', name: 'Trigger Sync', description: 'Manually trigger feed sync jobs.' },
            ],
            isSystem: true,
        },
        {
            id: 'system',
            name: 'System Settings',
            icon: 'settings',
            permissions: [
                { id: 'system:read', name: 'View System Health', description: 'Access to service health, queue stats, and metrics.' },
                { id: 'system:write', name: 'Modify Settings', description: 'Update configuration values and service connections.' },
                { id: 'system:maintenance', name: 'Platform Maintenance', description: 'Trigger cache clears, reindexing, and queue drains.' },
                { id: 'audit:read', name: 'Audit Logs', description: 'View system-wide activity logs.' },
            ],
            isSystem: true,
        },
        {
            id: 'users',
            name: 'User Management',
            icon: 'group',
            permissions: [
                { id: 'users:read', name: 'View Users', description: 'See team member list and roles.' },
                { id: 'users:write', name: 'Manage Users', description: 'Invite, edit, and deactivate users.' },
                { id: 'users:roles', name: 'Assign Roles', description: 'Change user roles and permissions.' },
            ],
            isSystem: true,
        },
    ];

    for (const mod of modules) {
        await db.insert(permissionModules).values({
            ...mod,
            createdAt: new Date(),
            updatedAt: new Date(),
        }).onConflictDoNothing();
    }

    console.log(`✓ Seeded ${modules.length} permission modules`);
}

// ============================================================================
// Seed Default Admin User (with auto-generated API token)
// ============================================================================

async function seedUsers() {
    console.log('Seeding default admin user...');

    const token = generateApiToken();

    await db.insert(users).values({
        id: randomUUID(),
        email: 'admin@rinjani.io',
        name: 'System Admin',
        roles: ['admin'],
        permissions: ['*'],
        isActive: true,
        apiToken: token,
        createdAt: new Date(),
        updatedAt: new Date(),
    }).onConflictDoNothing();

    console.log(`✓ Default admin user created`);
    console.log(`  Email: admin@rinjani.io`);
    console.log(`  API Token: ${token}`);
    console.log(`  ⚠ Save this token — it won't be shown again!`);
}

async function seedIOCs(count: number = 100) {
    console.log(`Seeding ${count} IOCs...`);

    const iocData = Array.from({ length: count }, () => {
        const type = randomItem(IOC_TYPES);
        let value: string;

        switch (type) {
            case 'ip':
                value = randomIP();
                break;
            case 'domain':
            case 'hostname':
                value = randomDomain();
                break;
            case 'url':
                value = `https://${randomDomain()}/path/${Math.random().toString(36).substring(7)}`;
                break;
            case 'hash-md5':
                value = randomHash().substring(0, 32);
                break;
            case 'hash-sha256':
                value = randomHash();
                break;
            case 'email':
                value = `user${Math.floor(Math.random() * 1000)}@${randomDomain()}`;
                break;
            default:
                value = randomDomain();
        }

        const now = new Date();
        const daysAgo = Math.floor(Math.random() * 90);
        const firstSeen = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000);

        return {
            id: randomUUID(),
            type,
            value,
            source: randomItem(SOURCES),
            threatType: randomItem(THREAT_TYPES),
            confidence: Math.floor(Math.random() * 100),
            severity: randomItem(SEVERITIES),
            firstSeen,
            lastSeen: now,
            tags: [randomItem(['malicious', 'suspicious', 'known-bad', 'apt'])],
            createdAt: firstSeen,
            updatedAt: now,
        };
    });

    await db.insert(iocs).values(iocData).onConflictDoNothing();
    console.log(`✓ Inserted ${iocData.length} IOCs`);
}

async function seedVulnerabilities(count: number = 20) {
    console.log(`Seeding ${count} vulnerabilities...`);

    const vulnData = Array.from({ length: count }, (_, i) => {
        const year = 2024 - Math.floor(i / 10);
        const num = 10000 + i;

        return {
            id: randomUUID(),
            cveId: `CVE-${year}-${num}`,
            vendorProject: randomItem(['Microsoft', 'Apple', 'Google', 'Linux', 'Apache']),
            product: randomItem(['Windows', 'Chrome', 'Office', 'Server', 'Framework']),
            vulnerabilityName: `Security Vulnerability ${num}`,
            dateAdded: new Date(),
            shortDescription: `A critical vulnerability was discovered affecting the product.`,
            requiredAction: 'Apply vendor patches or mitigations.',
            knownRansomware: Math.random() > 0.8,
            cvssScore: (Math.random() * 10).toFixed(1),
            severity: randomItem(SEVERITIES),
            createdAt: new Date(),
            updatedAt: new Date(),
        };
    });

    await db.insert(vulnerabilities).values(vulnData).onConflictDoNothing();
    console.log(`✓ Inserted ${vulnData.length} vulnerabilities`);
}

async function seedThreatActors(count: number = 10) {
    console.log(`Seeding ${count} threat actors...`);

    const now = new Date();

    const actorDefs = [
        { name: 'Lazarus Group', aliases: ['Hidden Cobra', 'APT38'], country: 'North Korea', motivation: 'financial-gain', sophistication: 'expert' },
        { name: 'Cozy Bear', aliases: ['APT29', 'The Dukes', 'Nobelium'], country: 'Russia', motivation: 'espionage', sophistication: 'advanced' },
        { name: 'Wizard Spider', aliases: ['Gold Blackburn', 'UNC1878'], country: 'Russia', motivation: 'financial-gain', sophistication: 'intermediate' },
        { name: 'OilRig', aliases: ['APT34', 'Helix Kitten'], country: 'Iran', motivation: 'espionage', sophistication: 'advanced' },
        { name: 'Turla', aliases: ['Venomous Bear', 'Snake'], country: 'Russia', motivation: 'espionage', sophistication: 'expert' },
        { name: 'Fancy Bear', aliases: ['APT28', 'Sofacy'], country: 'Russia', motivation: 'espionage', sophistication: 'expert' },
        { name: 'DarkSide', aliases: ['Carbon Spider'], country: 'Russia', motivation: 'financial-gain', sophistication: 'intermediate' },
        { name: 'Kimsuky', aliases: ['Velvet Chollima', 'APT43'], country: 'North Korea', motivation: 'espionage', sophistication: 'advanced' },
        { name: 'LockBit', aliases: ['ABCD Ransomware'], country: 'Unknown', motivation: 'financial-gain', sophistication: 'intermediate' },
        { name: 'Charming Kitten', aliases: ['APT35', 'Phosphorus'], country: 'Iran', motivation: 'ideology', sophistication: 'intermediate' },
        { name: 'Sandworm', aliases: ['Voodoo Bear', 'IRIDIUM'], country: 'Russia', motivation: 'dominance', sophistication: 'expert' },
        { name: 'Mustang Panda', aliases: ['TA416', 'Bronze President'], country: 'China', motivation: 'espionage', sophistication: 'advanced' },
    ];

    const actorData = actorDefs.slice(0, count).map((def, i) => {
        const daysAgo = Math.floor(Math.random() * 180) + 1;
        const firstSeen = new Date(now.getTime() - (daysAgo + 365) * 24 * 60 * 60 * 1000);
        const lastSeen = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000);

        return {
            id: randomUUID(),
            stixId: `threat-actor--${randomUUID()}`,
            name: def.name,
            description: `${def.name} is a sophisticated threat actor known for targeted attacks.`,
            aliases: def.aliases,
            sophistication: def.sophistication,
            resourceLevel: randomItem(['team', 'organization', 'government']),
            primaryMotivation: def.motivation,
            country: def.country,
            firstSeen,
            lastSeen,
            labels: ['threat-actor'],
            createdAt: new Date(),
            updatedAt: new Date(),
        };
    });

    await db.insert(threatActors).values(actorData).onConflictDoNothing();
    console.log(`✓ Inserted ${actorData.length} threat actors`);
}

// ============================================================================
// Seed Audit Logs (sample entries so the audit page isn't empty)
// ============================================================================

async function seedAuditLogs() {
    console.log('Seeding audit log entries...');

    const entityTypes = ['ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware'] as const;
    const actions = ['create', 'update', 'delete', 'enrich'] as const;
    const sources = ['feed-sync', 'api', 'manual', 'system', 'enrichment-worker'];

    const entries = [
        {
            entityType: 'ioc' as const,
            entityId: randomUUID(),
            action: 'create' as const,
            source: 'feed-sync',
            changes: { after: { value: '185.220.101.45', type: 'ip', source: 'AlienVault_OTX' } },
            metadata: { requestId: randomUUID(), reason: 'OTX pulse ingestion' },
        },
        {
            entityType: 'ioc' as const,
            entityId: randomUUID(),
            action: 'enrich' as const,
            source: 'enrichment-worker',
            changes: { before: { riskScore: 0 }, after: { riskScore: 85, enrichedAt: new Date().toISOString() } },
            metadata: { requestId: randomUUID(), reason: 'VirusTotal enrichment completed' },
        },
        {
            entityType: 'vulnerability' as const,
            entityId: randomUUID(),
            action: 'create' as const,
            source: 'feed-sync',
            changes: { after: { cveId: 'CVE-2024-21762', severity: 'critical', vendor: 'Fortinet' } },
            metadata: { requestId: randomUUID(), reason: 'CISA KEV sync' },
        },
        {
            entityType: 'vulnerability' as const,
            entityId: randomUUID(),
            action: 'update' as const,
            source: 'system',
            changes: { before: { cvssScore: '8.1' }, after: { cvssScore: '9.8' }, diff: [{ field: 'cvssScore', old: '8.1', new: '9.8' }] },
            metadata: { requestId: randomUUID(), reason: 'NVD score update' },
        },
        {
            entityType: 'threat_actor' as const,
            entityId: randomUUID(),
            action: 'create' as const,
            source: 'feed-sync',
            changes: { after: { name: 'APT28', aliases: ['Fancy Bear'], sophistication: 'expert' } },
            metadata: { requestId: randomUUID(), reason: 'MITRE ATT&CK sync' },
        },
        {
            entityType: 'threat_actor' as const,
            entityId: randomUUID(),
            action: 'update' as const,
            source: 'manual',
            changes: { before: { description: 'Known APT group' }, after: { description: 'Russian military intelligence GRU Unit 26165' } },
            metadata: { requestId: randomUUID(), reason: 'Analyst manual update' },
        },
        {
            entityType: 'ioc' as const,
            entityId: randomUUID(),
            action: 'delete' as const,
            source: 'api',
            changes: { before: { value: '192.168.1.1', type: 'ip', reason: 'false positive' } },
            metadata: { requestId: randomUUID(), reason: 'Removed false positive' },
        },
        {
            entityType: 'malware' as const,
            entityId: randomUUID(),
            action: 'create' as const,
            source: 'feed-sync',
            changes: { after: { name: 'Emotet', type: 'trojan', platform: 'windows' } },
            metadata: { requestId: randomUUID(), reason: 'MalwareBazaar sync' },
        },
        {
            entityType: 'pulse' as const,
            entityId: randomUUID(),
            action: 'create' as const,
            source: 'feed-sync',
            changes: { after: { title: 'Active Campaign Targeting Financial Sector', indicators: 47 } },
            metadata: { requestId: randomUUID(), reason: 'OTX pulse ingestion' },
        },
        {
            entityType: 'ioc' as const,
            entityId: randomUUID(),
            action: 'enrich' as const,
            source: 'enrichment-worker',
            changes: { before: { riskScore: 30 }, after: { riskScore: 95, vtMalicious: 42, vtTotal: 70 } },
            metadata: { requestId: randomUUID(), reason: 'VirusTotal flagged as highly malicious' },
        },
        {
            entityType: 'indicator' as const,
            entityId: randomUUID(),
            action: 'create' as const,
            source: 'feed-sync',
            changes: { after: { pattern: "[file:hashes.'SHA-256' = 'abc123']", validFrom: new Date().toISOString() } },
            metadata: { requestId: randomUUID(), reason: 'STIX indicator ingestion' },
        },
        {
            entityType: 'vulnerability' as const,
            entityId: randomUUID(),
            action: 'enrich' as const,
            source: 'enrichment-worker',
            changes: { before: { exploitAvailable: false }, after: { exploitAvailable: true, exploitMaturity: 'proof-of-concept' } },
            metadata: { requestId: randomUUID(), reason: 'NVD enrichment — exploit detected' },
        },
    ];

    // Spread entries over the last 30 days
    const now = Date.now();
    const auditData = entries.map((entry, i) => ({
        ...entry,
        createdAt: new Date(now - (i * 2 + Math.random()) * 24 * 60 * 60 * 1000),
    }));

    await db.insert(auditLogs).values(auditData).onConflictDoNothing();
    console.log(`✓ Inserted ${auditData.length} audit log entries`);
}

async function main() {
    console.log('Starting database seed...\n');

    try {
        // RBAC seed (always run first)
        await seedRoles();
        await seedPermissionModules();
        await seedUsers();

        // Sample data
        await seedIOCs(100);
        await seedVulnerabilities(20);
        await seedThreatActors(10);
        await seedAuditLogs();

        console.log('\n✓ Database seeded successfully!');
    } catch (error) {
        console.error('Seed failed:', error);
        process.exit(1);
    }

    process.exit(0);
}

main();

