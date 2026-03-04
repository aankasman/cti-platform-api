/**
 * OpenAPI Paths — V1 core endpoints (Health, Auth, CRUD, Search, Export, Enrich, Monitoring, Webhooks, Audit, Opengate)
 */

export const pathsV1 = {
    // Health
    '/health': {
        get: {
            tags: ['Health'],
            summary: 'Health check',
            security: [],
            responses: {
                '200': {
                    description: 'API is healthy',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    status: { type: 'string', example: 'healthy' },
                                    version: { type: 'string', example: '1.0.0' },
                                    timestamp: { type: 'string', format: 'date-time' },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    // Auth
    '/auth/login': {
        post: {
            tags: ['Auth'],
            summary: 'Login and get JWT token',
            security: [],
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                username: { type: 'string' },
                                password: { type: 'string' },
                                api_key: { type: 'string' },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': {
                    description: 'Login successful',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    success: { type: 'boolean' },
                                    token: { type: 'string' },
                                    expiresIn: { type: 'string' },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    '/auth/verify': {
        get: {
            tags: ['Auth'],
            summary: 'Verify current authentication',
            responses: {
                '200': { description: 'Token is valid' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    // Vulnerabilities
    '/v1/vulnerabilities': {
        get: {
            tags: ['Vulnerabilities'],
            summary: 'List vulnerabilities',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
                { name: 'severity', in: 'query', schema: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] } },
                { name: 'exploited', in: 'query', schema: { type: 'boolean' } },
                { name: 'vendor', in: 'query', schema: { type: 'string' } },
                { name: 'dateFrom', in: 'query', schema: { type: 'string', format: 'date' } },
                { name: 'dateTo', in: 'query', schema: { type: 'string', format: 'date' } },
                { name: 'q', in: 'query', schema: { type: 'string' }, description: 'Search CVE ID or description' },
            ],
            responses: {
                '200': {
                    description: 'List of vulnerabilities',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object',
                                        properties: {
                                            items: { type: 'array', items: { $ref: '#/components/schemas/Vulnerability' } },
                                            pagination: { $ref: '#/components/schemas/Pagination' },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    '/v1/vulnerabilities/{cveId}': {
        get: {
            tags: ['Vulnerabilities'],
            summary: 'Get vulnerability by CVE ID',
            parameters: [{ name: 'cveId', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Vulnerability details' },
                '404': { description: 'CVE not found' },
            },
        },
    },
    // IOCs
    '/v1/iocs': {
        get: {
            tags: ['IOCs'],
            summary: 'List IOCs',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
                { name: 'type', in: 'query', schema: { type: 'string', enum: ['ip', 'domain', 'url', 'hash', 'email'] } },
                { name: 'source', in: 'query', schema: { type: 'string' } },
                { name: 'threatType', in: 'query', schema: { type: 'string', enum: ['c2', 'malware', 'phishing', 'botnet'] } },
                { name: 'q', in: 'query', schema: { type: 'string' } },
            ],
            responses: {
                '200': {
                    description: 'List of IOCs',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object',
                                        properties: {
                                            items: { type: 'array', items: { $ref: '#/components/schemas/IOC' } },
                                            pagination: { $ref: '#/components/schemas/Pagination' },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    '/v1/iocs/{value}': {
        get: {
            tags: ['IOCs'],
            summary: 'Get IOC by value',
            parameters: [{ name: 'value', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'IOC details' },
                '404': { description: 'IOC not found' },
            },
        },
    },
    // Threats
    '/v1/threats': {
        get: {
            tags: ['Threats'],
            summary: 'List threat actors',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
            ],
            responses: { '200': { description: 'List of threat actors' } },
        },
    },
    '/v1/threat-actors': {
        get: {
            tags: ['Threats'],
            summary: 'List MITRE threat actors',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
                { name: 'q', in: 'query', schema: { type: 'string' } },
            ],
            responses: { '200': { description: 'List of threat actors' } },
        },
    },
    // MITRE ATT&CK
    '/v1/tactics': {
        get: {
            tags: ['MITRE ATT&CK'],
            summary: 'List MITRE ATT&CK tactics',
            responses: { '200': { description: 'List of tactics' } },
        },
    },
    '/v1/techniques': {
        get: {
            tags: ['MITRE ATT&CK'],
            summary: 'List MITRE ATT&CK techniques',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 50 } },
                { name: 'q', in: 'query', schema: { type: 'string' } },
                { name: 'platform', in: 'query', schema: { type: 'string' } },
                { name: 'tactic', in: 'query', schema: { type: 'string' } },
            ],
            responses: { '200': { description: 'List of techniques' } },
        },
    },
    '/v1/techniques/{mitreId}': {
        get: {
            tags: ['MITRE ATT&CK'],
            summary: 'Get technique by MITRE ID',
            parameters: [{ name: 'mitreId', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '200': { description: 'Technique details' }, '404': { description: 'Not found' } },
        },
    },
    '/v1/malware': {
        get: {
            tags: ['MITRE ATT&CK'],
            summary: 'List MITRE malware',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
            ],
            responses: { '200': { description: 'List of malware' } },
        },
    },
    '/v1/tools': {
        get: {
            tags: ['MITRE ATT&CK'],
            summary: 'List MITRE tools',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
            ],
            responses: { '200': { description: 'List of tools' } },
        },
    },
    // Pulses
    '/v1/pulses': {
        get: {
            tags: ['Pulses'],
            summary: 'List AlienVault OTX pulses',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
            ],
            responses: { '200': { description: 'List of pulses' } },
        },
    },
    // Stats
    '/v1/stats': {
        get: {
            tags: ['Monitoring'],
            summary: 'Get overall statistics',
            responses: { '200': { description: 'Statistics data' } },
        },
    },
    '/v1/stats/distribution': {
        get: {
            tags: ['Monitoring'],
            summary: 'Get IOC distribution by type',
            responses: { '200': { description: 'Distribution data' } },
        },
    },
    // Search
    '/v1/search': {
        get: {
            tags: ['Search'],
            summary: 'Quick search',
            parameters: [
                { name: 'q', in: 'query', required: true, schema: { type: 'string' } },
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 25 } },
            ],
            responses: { '200': { description: 'Search results' } },
        },
    },
    '/v1/search/iocs': {
        post: {
            tags: ['Search'],
            summary: 'Advanced IOC search',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                query: { type: 'string' },
                                filters: {
                                    type: 'object',
                                    properties: {
                                        type: { type: 'string' },
                                        source: { type: 'string' },
                                        threatType: { type: 'string' },
                                        minConfidence: { type: 'integer' },
                                        maxConfidence: { type: 'integer' },
                                        dateFrom: { type: 'string', format: 'date' },
                                        dateTo: { type: 'string', format: 'date' },
                                    },
                                },
                                sort: {
                                    type: 'object',
                                    properties: {
                                        field: { type: 'string' },
                                        order: { type: 'string', enum: ['asc', 'desc'] },
                                    },
                                },
                                pagination: {
                                    type: 'object',
                                    properties: {
                                        page: { type: 'integer' },
                                        limit: { type: 'integer' },
                                    },
                                },
                                aggregations: { type: 'boolean' },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'Search results with aggregations' } },
        },
    },
    '/v1/search/vulnerabilities': {
        post: {
            tags: ['Search'],
            summary: 'Advanced vulnerability search',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                query: { type: 'string' },
                                filters: {
                                    type: 'object',
                                    properties: {
                                        severity: { type: 'string' },
                                        isExploited: { type: 'boolean' },
                                        vendor: { type: 'string' },
                                        minCvss: { type: 'number' },
                                        maxCvss: { type: 'number' },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'Search results' } },
        },
    },
    // Export
    '/v1/export/iocs/csv': {
        post: {
            tags: ['Export'],
            summary: 'Export IOCs to CSV',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                filters: { type: 'object' },
                                limit: { type: 'integer', default: 10000 },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'CSV data' } },
        },
    },
    '/v1/export/iocs/json': {
        post: {
            tags: ['Export'],
            summary: 'Export IOCs to JSON',
            responses: { '200': { description: 'JSON data' } },
        },
    },
    '/v1/export/iocs/stix': {
        post: {
            tags: ['Export'],
            summary: 'Export IOCs to STIX 2.1 format',
            responses: { '200': { description: 'STIX bundle' } },
        },
    },
    '/v1/export/vulnerabilities/csv': {
        post: {
            tags: ['Export'],
            summary: 'Export vulnerabilities to CSV',
            responses: { '200': { description: 'CSV data' } },
        },
    },
    '/v1/export/vulnerabilities/json': {
        post: {
            tags: ['Export'],
            summary: 'Export vulnerabilities to JSON',
            responses: { '200': { description: 'JSON data' } },
        },
    },
    // Enrich
    '/v1/enrich/ip/{ip}': {
        get: {
            tags: ['Enrich'],
            summary: 'Enrich IP address',
            parameters: [{ name: 'ip', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '200': { description: 'Enriched IP data' }, '404': { description: 'IP not found' } },
        },
    },
    '/v1/enrich/domain/{domain}': {
        get: {
            tags: ['Enrich'],
            summary: 'Enrich domain',
            parameters: [{ name: 'domain', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '200': { description: 'Enriched domain data' }, '404': { description: 'Domain not found' } },
        },
    },
    '/v1/enrich/hash/{hash}': {
        get: {
            tags: ['Enrich'],
            summary: 'Enrich file hash',
            parameters: [{ name: 'hash', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '200': { description: 'Enriched hash data' }, '404': { description: 'Hash not found' } },
        },
    },
    '/v1/enrich/bulk': {
        post: {
            tags: ['Enrich'],
            summary: 'Bulk IOC enrichment (max 100)',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['values'],
                            properties: {
                                values: { type: 'array', items: { type: 'string' }, maxItems: 100 },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'Bulk enrichment results' } },
        },
    },
    // Monitoring
    '/v1/monitoring/feeds': {
        get: {
            tags: ['Monitoring'],
            summary: 'Get all feed health status',
            responses: {
                '200': {
                    description: 'Feed health data',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object',
                                        properties: {
                                            feeds: { type: 'array', items: { $ref: '#/components/schemas/FeedHealth' } },
                                            summary: {
                                                type: 'object',
                                                properties: {
                                                    total: { type: 'integer' },
                                                    healthy: { type: 'integer' },
                                                    warning: { type: 'integer' },
                                                    critical: { type: 'integer' },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    '/v1/monitoring/feeds/{feedId}': {
        get: {
            tags: ['Monitoring'],
            summary: 'Get specific feed status',
            parameters: [{ name: 'feedId', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '200': { description: 'Feed details' } },
        },
    },
    '/v1/monitoring/health': {
        get: {
            tags: ['Monitoring'],
            summary: 'Get overall system health',
            responses: { '200': { description: 'System health status' } },
        },
    },
    '/v1/monitoring/metrics/growth': {
        get: {
            tags: ['Monitoring'],
            summary: 'Get IOC/vulnerability growth metrics',
            parameters: [
                { name: 'days', in: 'query', schema: { type: 'integer', default: 7 } },
                { name: 'granularity', in: 'query', schema: { type: 'string', enum: ['day', 'hour'] } },
            ],
            responses: { '200': { description: 'Growth metrics' } },
        },
    },
    // Opengate
    '/opengate/keys': {
        get: {
            tags: ['Opengate'],
            summary: 'List your API keys',
            responses: { '200': { description: 'List of API keys' } },
        },
        post: {
            tags: ['Opengate'],
            summary: 'Generate new API key',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                name: { type: 'string' },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'New API key (only shown once)' } },
        },
    },
    '/opengate/keys/{id}': {
        delete: {
            tags: ['Opengate'],
            summary: 'Revoke an API key',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '200': { description: 'Key revoked' } },
        },
    },
    '/opengate/profile': {
        get: {
            tags: ['Opengate'],
            summary: 'Get user profile',
            responses: { '200': { description: 'User profile data' } },
        },
    },
    '/opengate/usage': {
        get: {
            tags: ['Opengate'],
            summary: 'Get API usage statistics',
            responses: { '200': { description: 'Usage statistics' } },
        },
    },
    // Webhooks
    '/v1/webhooks': {
        get: {
            tags: ['Webhooks'],
            summary: 'List webhooks',
            responses: { '200': { description: 'List of webhooks' } },
        },
        post: {
            tags: ['Webhooks'],
            summary: 'Create webhook',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['url', 'events'],
                            properties: {
                                url: { type: 'string', format: 'uri' },
                                events: { type: 'array', items: { type: 'string' } },
                                secret: { type: 'string' },
                            },
                        },
                    },
                },
            },
            responses: { '201': { description: 'Webhook created' } },
        },
    },
    '/v1/webhooks/events': {
        get: {
            tags: ['Webhooks'],
            summary: 'List available webhook events',
            responses: { '200': { description: 'Available events' } },
        },
    },
    '/v1/webhooks/{id}': {
        delete: {
            tags: ['Webhooks'],
            summary: 'Delete webhook',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: { '204': { description: 'Webhook deleted' } },
        },
    },
    // Audit
    '/v1/audit': {
        get: {
            tags: ['Audit'],
            summary: 'Get audit logs',
            parameters: [
                { name: 'action', in: 'query', schema: { type: 'string' } },
                { name: 'entityType', in: 'query', schema: { type: 'string' } },
                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
                { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
            ],
            responses: { '200': { description: 'Audit logs' } },
        },
    },
    '/v1/audit/stats': {
        get: {
            tags: ['Audit'],
            summary: 'Get audit statistics',
            responses: { '200': { description: 'Audit statistics' } },
        },
    },
    '/v1/audit/entity/{type}/{id}': {
        get: {
            tags: ['Audit'],
            summary: 'Get entity audit history',
            parameters: [
                { name: 'type', in: 'path', required: true, schema: { type: 'string' } },
                { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
            ],
            responses: { '200': { description: 'Entity audit history' } },
        },
    },
} as const;
