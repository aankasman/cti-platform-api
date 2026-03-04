/**
 * OpenAPI Schemas — Component schemas for the API specification
 */

export const schemas = {
    Pagination: {
        type: 'object',
        properties: {
            page: { type: 'integer', example: 1 },
            pageSize: { type: 'integer', example: 25 },
            totalItems: { type: 'integer', example: 1000 },
            totalPages: { type: 'integer', example: 40 },
        },
    },
    Error: {
        type: 'object',
        properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string', example: 'Error message' },
        },
    },
    Vulnerability: {
        type: 'object',
        properties: {
            id: { type: 'string', format: 'uuid' },
            cveId: { type: 'string', example: 'CVE-2024-1234' },
            description: { type: 'string' },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
            cvssScore: { type: 'number', example: 9.8 },
            vendorProject: { type: 'string', example: 'Microsoft' },
            product: { type: 'string', example: 'Windows' },
            isExploited: { type: 'boolean' },
            exploitAddedDate: { type: 'string', format: 'date' },
            publishedDate: { type: 'string', format: 'date-time' },
        },
    },
    IOC: {
        type: 'object',
        properties: {
            id: { type: 'string', format: 'uuid' },
            value: { type: 'string', example: '192.168.1.1' },
            type: { type: 'string', enum: ['ip', 'domain', 'url', 'hash', 'email'] },
            source: { type: 'string', example: 'alienvault' },
            threatType: { type: 'string', enum: ['c2', 'malware', 'phishing', 'botnet'] },
            confidence: { type: 'integer', minimum: 0, maximum: 100 },
            tags: { type: 'array', items: { type: 'string' } },
            firstSeen: { type: 'string', format: 'date-time' },
            lastSeen: { type: 'string', format: 'date-time' },
        },
    },
    ThreatActor: {
        type: 'object',
        properties: {
            id: { type: 'string', format: 'uuid' },
            name: { type: 'string', example: 'APT29' },
            aliases: { type: 'array', items: { type: 'string' } },
            description: { type: 'string' },
            country: { type: 'string' },
            motivations: { type: 'array', items: { type: 'string' } },
            updatedAt: { type: 'string', format: 'date-time' },
        },
    },
    Technique: {
        type: 'object',
        properties: {
            id: { type: 'string', format: 'uuid' },
            mitreId: { type: 'string', example: 'T1059' },
            name: { type: 'string', example: 'Command and Scripting Interpreter' },
            description: { type: 'string' },
            platforms: { type: 'array', items: { type: 'string' } },
            tacticIds: { type: 'array', items: { type: 'string' } },
        },
    },
    FeedHealth: {
        type: 'object',
        properties: {
            feed: { type: 'string' },
            health: { type: 'string', enum: ['healthy', 'warning', 'critical'] },
            status: { type: 'string' },
            lastSync: { type: 'string', format: 'date-time' },
            itemsProcessed: { type: 'integer' },
            itemsFailed: { type: 'integer' },
            successRate: { type: 'integer' },
            duration: { type: 'integer' },
        },
    },
    GraphNode: {
        type: 'object',
        properties: {
            id: { type: 'string', description: 'Unique node identifier (stixId, mitreId, pgId, etc.)' },
            label: { type: 'string', description: 'Display label for the node', example: 'APT29' },
            type: { type: 'string', description: 'Node type (Actor, Technique, IOC, etc.)', example: 'Actor' },
            properties: { type: 'object', description: 'Additional node properties', additionalProperties: true },
        },
    },
    GraphEdge: {
        type: 'object',
        properties: {
            source: { type: 'string', description: 'Source node ID' },
            target: { type: 'string', description: 'Target node ID' },
            type: { type: 'string', description: 'Relationship type', example: 'USES' },
            properties: { type: 'object', description: 'Additional edge properties', additionalProperties: true },
        },
    },
    GraphResult: {
        type: 'object',
        properties: {
            nodes: { type: 'array', items: { $ref: '#/components/schemas/GraphNode' } },
            edges: { type: 'array', items: { $ref: '#/components/schemas/GraphEdge' } },
            meta: { type: 'object', additionalProperties: true },
        },
    },
    Alert: {
        type: 'object',
        properties: {
            id: { type: 'string' },
            type: { type: 'string', enum: ['new_ioc', 'new_vulnerability', 'enrichment_complete', 'critical_threat', 'system_alert'] },
            severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
            title: { type: 'string', example: 'New critical IOC detected' },
            message: { type: 'string' },
            read: { type: 'boolean', default: false },
            source: { type: 'string', example: 'feed-sync' },
            metadata: { type: 'object', additionalProperties: true },
            createdAt: { type: 'string', format: 'date-time' },
        },
    },
    User: {
        type: 'object',
        properties: {
            id: { type: 'string', example: 'usr-001' },
            email: { type: 'string', format: 'email', example: 'analyst@rinjani.io' },
            name: { type: 'string', example: 'Security Analyst' },
            role: { type: 'string', enum: ['admin', 'analyst', 'viewer'] },
            status: { type: 'string', enum: ['active', 'inactive', 'pending'] },
            createdAt: { type: 'string', format: 'date-time' },
            lastLogin: { type: 'string', format: 'date-time' },
        },
    },
    NotificationSettings: {
        type: 'object',
        properties: {
            emailEnabled: { type: 'boolean', default: false },
            emailAddress: { type: 'string', format: 'email', nullable: true },
            slackEnabled: { type: 'boolean', default: false },
            slackWebhookUrl: { type: 'string', nullable: true },
            severityThreshold: { type: 'string', enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
            notifyOnNewIOC: { type: 'boolean', default: true },
            notifyOnNewVuln: { type: 'boolean', default: true },
            notifyOnThreatActor: { type: 'boolean', default: true },
        },
    },
    QueueStats: {
        type: 'object',
        properties: {
            waiting: { type: 'integer' },
            active: { type: 'integer' },
            completed: { type: 'integer' },
            failed: { type: 'integer' },
            delayed: { type: 'integer' },
        },
    },
    SystemHealth: {
        type: 'object',
        properties: {
            status: { type: 'string', enum: ['healthy', 'degraded', 'critical'] },
            services: {
                type: 'object',
                properties: {
                    postgresql: { type: 'object', properties: { status: { type: 'string' }, activeConnections: { type: 'integer' }, queryLatencyMs: { type: 'integer' } } },
                    redis: { type: 'object', properties: { status: { type: 'string' }, memoryUsedMB: { type: 'integer' }, connectedClients: { type: 'integer' }, opsPerSec: { type: 'integer' } } },
                    opensearch: { type: 'object', properties: { status: { type: 'string' }, nodeCount: { type: 'integer' }, indexCount: { type: 'integer' }, documentCount: { type: 'integer' } } },
                    neo4j: { type: 'object', properties: { status: { type: 'string' }, connected: { type: 'boolean' }, nodeCount: { type: 'integer' }, relationshipCount: { type: 'integer' } } },
                },
            },
            timestamp: { type: 'string', format: 'date-time' },
        },
    },
    JobStatus: {
        type: 'object',
        properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            queue: { type: 'string' },
            state: { type: 'string', enum: ['waiting', 'active', 'completed', 'failed', 'delayed'] },
            progress: { type: 'integer' },
            data: { type: 'object', additionalProperties: true },
            result: { type: 'object', additionalProperties: true },
            failedReason: { type: 'string', nullable: true },
            attemptsMade: { type: 'integer' },
            timestamp: { type: 'number' },
            processedOn: { type: 'number', nullable: true },
            finishedOn: { type: 'number', nullable: true },
        },
    },
    FeedConfig: {
        type: 'object',
        properties: {
            id: { type: 'string', example: 'otx-sync' },
            name: { type: 'string', example: 'AlienVault OTX' },
            source: { type: 'string', example: 'otx' },
            description: { type: 'string' },
            cron: { type: 'string', example: '*/15 * * * *' },
            enabled: { type: 'boolean' },
            category: { type: 'string', enum: ['high-frequency', 'ioc-feeds', 'knowledge-base', 'nexus', 'custom-api', 'rss', 'financial', 'osint'] },
            requiresApiKey: { type: 'string', nullable: true },
            custom: { type: 'boolean' },
            url: { type: 'string', nullable: true },
            authHeader: { type: 'string', nullable: true },
            authKeyRef: { type: 'string', nullable: true },
            format: { type: 'string', enum: ['json', 'csv', 'rss', 'stix', 'text'], nullable: true },
        },
    },
    ApiKeyConfig: {
        type: 'object',
        properties: {
            id: { type: 'string', example: 'virustotal' },
            name: { type: 'string', example: 'VirusTotal (Standard)' },
            provider: { type: 'string', example: 'VirusTotal' },
            envVar: { type: 'string', example: 'VIRUSTOTAL_API_KEY' },
            maskedValue: { type: 'string', nullable: true, example: '****abcd' },
            configured: { type: 'boolean' },
            testEndpoint: { type: 'string', nullable: true },
            custom: { type: 'boolean' },
            authHeaderName: { type: 'string', nullable: true },
        },
    },
    ServiceConfig: {
        type: 'object',
        properties: {
            id: { type: 'string', example: 'postgresql' },
            name: { type: 'string', example: 'PostgreSQL' },
            envVars: {
                type: 'array',
                items: {
                    type: 'object',
                    properties: {
                        key: { type: 'string' },
                        label: { type: 'string' },
                        secret: { type: 'boolean' },
                    },
                },
            },
            custom: { type: 'boolean' },
            values: { type: 'object', additionalProperties: { type: 'string', nullable: true } },
        },
    },
    Role: {
        type: 'object',
        properties: {
            id: { type: 'string', example: 'admin' },
            name: { type: 'string', example: 'Administrator' },
            description: { type: 'string' },
            defaultPermissions: { type: 'array', items: { type: 'string' } },
            isSystem: { type: 'boolean' },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
        },
    },
    PermissionModule: {
        type: 'object',
        properties: {
            id: { type: 'string', example: 'threat-intel' },
            name: { type: 'string', example: 'Threat Intelligence Access' },
            icon: { type: 'string', example: 'radar' },
            permissions: {
                type: 'array',
                items: {
                    type: 'object',
                    properties: {
                        id: { type: 'string' },
                        name: { type: 'string' },
                        description: { type: 'string' },
                    },
                },
            },
            isSystem: { type: 'boolean' },
        },
    },
    AuditEntry: {
        type: 'object',
        properties: {
            id: { type: 'string', format: 'uuid' },
            entityType: { type: 'string', enum: ['ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware'] },
            entityId: { type: 'string', format: 'uuid' },
            action: { type: 'string', enum: ['create', 'update', 'delete', 'merge', 'enrich'] },
            userId: { type: 'string', format: 'uuid', nullable: true },
            source: { type: 'string', nullable: true },
            changes: { type: 'object', nullable: true },
            metadata: { type: 'object', nullable: true },
            createdAt: { type: 'string', format: 'date-time' },
        },
    },
    SandboxResult: {
        type: 'object',
        properties: {
            success: { type: 'boolean' },
            status: { type: 'integer', example: 200 },
            latencyMs: { type: 'integer', example: 342 },
            message: { type: 'string' },
            responseSnippet: { type: 'string', description: 'First 500 chars of response body' },
        },
    },
} as const;
