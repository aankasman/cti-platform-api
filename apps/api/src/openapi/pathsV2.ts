/**
 * OpenAPI Paths — V2 endpoints (OpenSearch, AI, Graph Explorer, STIX/Bulk)
 */

export const pathsV2 = {
    // OpenSearch
    '/v2/search': {
        post: {
            tags: ['OpenSearch'],
            summary: 'Unified full-text search',
            description: 'Search across IOCs, vulnerabilities, and actors via OpenSearch with faceted aggregations.',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                query: { type: 'string', example: 'ransomware' },
                                filters: { type: 'object', properties: { type: { type: 'string' }, source: { type: 'string' }, severity: { type: 'string' } } },
                                sort: { type: 'object', properties: { field: { type: 'string', default: 'updatedAt' }, order: { type: 'string', enum: ['asc', 'desc'], default: 'desc' } } },
                                pagination: { type: 'object', properties: { page: { type: 'integer', default: 1 }, limit: { type: 'integer', default: 25 } } },
                                aggregations: { type: 'boolean', default: true },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'Search results with faceted aggregations' } },
        },
    },
    '/v2/search/health': {
        get: {
            tags: ['OpenSearch'],
            summary: 'Check OpenSearch cluster health',
            responses: { '200': { description: 'OpenSearch health status' } },
        },
    },
    '/v2/search/reindex': {
        post: {
            tags: ['OpenSearch'],
            summary: 'Reindex all data from PostgreSQL (admin)',
            description: 'Reindexes all IOCs, vulnerabilities, and actors from PostgreSQL into OpenSearch.',
            responses: { '200': { description: 'Reindexing results' }, '401': { description: 'Unauthorized' } },
        },
    },
    '/v2/search/init': {
        post: {
            tags: ['OpenSearch'],
            summary: 'Initialize OpenSearch indices (admin)',
            responses: { '200': { description: 'Indices created' }, '401': { description: 'Unauthorized' } },
        },
    },
    '/v2/search/recreate': {
        post: {
            tags: ['OpenSearch'],
            summary: 'Recreate indices with vector mapping (admin)',
            description: '⚠️ Destructive — drops and recreates OpenSearch indices with knn_vector mapping, then reindexes all data with embeddings.',
            responses: { '200': { description: 'Index recreated and data reindexed' }, '401': { description: 'Unauthorized' } },
        },
    },
    // AI Analysis
    '/v2/ai/analyze': {
        post: {
            tags: ['AI'],
            summary: 'AI-powered entity analysis',
            description: 'Analyze any entity (IOC, CVE, or threat actor) using AI. Results are cached for fast subsequent retrieval.',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['entityType', 'entityId', 'entityData'],
                            properties: {
                                entityType: { type: 'string', enum: ['ioc', 'cve', 'actor'], example: 'ioc' },
                                entityId: { type: 'string', example: '192.168.1.100' },
                                entityData: { type: 'object', description: 'Full entity data object', additionalProperties: true },
                                forceRefresh: { type: 'boolean', default: false, description: 'Force regeneration of cached analysis' },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': { description: 'AI analysis results' },
                '400': { description: 'Missing or invalid fields' },
            },
        },
    },
    // Graph Explorer
    '/v2/graph/expand/{id}': {
        get: {
            tags: ['Graph Explorer'],
            summary: 'Neighborhood expansion',
            description: 'Expand N hops from any node. Accepts stixId, mitreId, cveId, IOC value, or entity name.',
            parameters: [
                { name: 'id', in: 'path', required: true, schema: { type: 'string' }, description: 'Node identifier (stixId, mitreId, cveId, value, or name)' },
                { name: 'depth', in: 'query', schema: { type: 'integer', default: 1, minimum: 1, maximum: 4 }, description: 'Number of hops (1–4)' },
                { name: 'limit', in: 'query', schema: { type: 'integer', default: 100, maximum: 500 }, description: 'Max nodes to return' },
            ],
            responses: {
                '200': {
                    description: 'Graph neighborhood',
                    content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/GraphResult' } } } } },
                },
            },
        },
    },
    '/v2/graph/path': {
        get: {
            tags: ['Graph Explorer'],
            summary: 'Shortest path between entities',
            description: 'Find the shortest path between two entities in the knowledge graph.',
            parameters: [
                { name: 'from', in: 'query', required: true, schema: { type: 'string' }, description: 'Source entity identifier' },
                { name: 'to', in: 'query', required: true, schema: { type: 'string' }, description: 'Target entity identifier' },
                { name: 'maxDepth', in: 'query', schema: { type: 'integer', default: 6, maximum: 10 }, description: 'Max path length' },
            ],
            responses: {
                '200': {
                    description: 'Shortest path result',
                    content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/GraphResult' } } } } },
                },
                '400': { description: 'Missing from/to parameters' },
            },
        },
    },
    '/v2/graph/attack-tree/{actor}': {
        get: {
            tags: ['Graph Explorer'],
            summary: 'ATT&CK tree for an actor',
            description: 'Full MITRE ATT&CK tree: Actor → Techniques → Tactics, plus associated Malware and Tools.',
            parameters: [
                { name: 'actor', in: 'path', required: true, schema: { type: 'string' }, description: 'Actor name or STIX ID', example: 'APT29' },
            ],
            responses: {
                '200': {
                    description: 'Attack tree graph',
                    content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/GraphResult' } } } } },
                },
            },
        },
    },
    '/v2/graph/ioc-pivot/{value}': {
        get: {
            tags: ['Graph Explorer'],
            summary: 'IOC pivot traversal',
            description: 'Pivot from an IOC through its Pulse to attributed Actors and their related IOCs.',
            parameters: [
                { name: 'value', in: 'path', required: true, schema: { type: 'string' }, description: 'IOC value (IP, domain, hash, etc.)' },
                { name: 'maxResults', in: 'query', schema: { type: 'integer', default: 50, maximum: 200 }, description: 'Max related nodes' },
            ],
            responses: {
                '200': {
                    description: 'IOC pivot graph',
                    content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/GraphResult' } } } } },
                },
            },
        },
    },
    '/v2/graph/related-actors/{actor}': {
        get: {
            tags: ['Graph Explorer'],
            summary: 'Related actors (shared techniques)',
            description: 'Find threat actors that share MITRE ATT&CK techniques with a given actor.',
            parameters: [
                { name: 'actor', in: 'path', required: true, schema: { type: 'string' }, description: 'Actor name or STIX ID' },
                { name: 'minShared', in: 'query', schema: { type: 'integer', default: 1, minimum: 1 }, description: 'Minimum shared techniques' },
            ],
            responses: {
                '200': {
                    description: 'Related actors graph',
                    content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/GraphResult' } } } } },
                },
            },
        },
    },
    '/v2/graph/cypher': {
        post: {
            tags: ['Graph Explorer'],
            summary: 'Execute raw Cypher query (admin)',
            description: 'Execute a read-only Cypher query against Neo4j. Write operations (CREATE, MERGE, DELETE, etc.) are blocked.',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['query'],
                            properties: {
                                query: { type: 'string', example: 'MATCH (a:Actor)-[:USES]->(t:Technique) RETURN a.name, t.name LIMIT 10' },
                                params: { type: 'object', description: 'Cypher query parameters', additionalProperties: true },
                                limit: { type: 'integer', default: 100, maximum: 500 },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': { description: 'Query results' },
                '400': { description: 'Missing query' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Write operations not allowed' },
            },
        },
    },
    // STIX Export
    '/v2/stix/bundle': {
        get: {
            tags: ['Export'],
            summary: 'Export data as STIX 2.1 bundle',
            parameters: [
                { name: 'includeIOCs', in: 'query', schema: { type: 'boolean', default: true } },
                { name: 'includeThreatActors', in: 'query', schema: { type: 'boolean', default: true } },
                { name: 'includeVulnerabilities', in: 'query', schema: { type: 'boolean', default: true } },
                { name: 'iocLimit', in: 'query', schema: { type: 'integer', default: 100 } },
            ],
            responses: {
                '200': {
                    description: 'STIX 2.1 bundle',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    type: { type: 'string', example: 'bundle' },
                                    id: { type: 'string', example: 'bundle--uuid' },
                                    spec_version: { type: 'string', example: '2.1' },
                                    objects: { type: 'array', items: { type: 'object' } },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    // Bulk Operations
    '/v2/bulk/lookup': {
        post: {
            tags: ['IOCs'],
            summary: 'Bulk IOC lookup (max 1000)',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['values'],
                            properties: {
                                values: { type: 'array', items: { type: 'string' }, maxItems: 1000 },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': {
                    description: 'Lookup results',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    summary: {
                                        type: 'object',
                                        properties: {
                                            total: { type: 'integer' },
                                            found: { type: 'integer' },
                                            notFound: { type: 'integer' },
                                        },
                                    },
                                    results: { type: 'array', items: { type: 'object' } },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    '/v2/bulk/export/iocs': {
        get: {
            tags: ['Export'],
            summary: 'Bulk export IOCs',
            parameters: [
                { name: 'format', in: 'query', schema: { type: 'string', enum: ['json', 'csv', 'stix'] } },
                { name: 'limit', in: 'query', schema: { type: 'integer', default: 10000 } },
            ],
            responses: { '200': { description: 'Exported data' } },
        },
    },
    '/v2/bulk/import/iocs': {
        post: {
            tags: ['IOCs'],
            summary: 'Bulk import IOCs',
            requestBody: {
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['items'],
                            properties: {
                                items: { type: 'array', items: { $ref: '#/components/schemas/IOC' } },
                            },
                        },
                    },
                },
            },
            responses: { '200': { description: 'Import results' } },
        },
    },
} as const;
