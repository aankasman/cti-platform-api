/**
 * OpenAPI 3.0.3 Specification for RinjaniAnalytics CTI API
 *
 * Assembled from decomposed sub-modules:
 *   - schemas.ts   → Component schemas
 *   - pathsV1.ts   → V1 core endpoints
 *   - pathsV2.ts   → V2 endpoints (OpenSearch, AI, Graph, STIX/Bulk)
 *   - pathsAdmin.ts → Admin & system endpoints
 */

import { schemas } from './schemas.js';
import { pathsV1 } from './pathsV1.js';
import { pathsV2 } from './pathsV2.js';
import { pathsAdmin } from './pathsAdmin.js';

export const openApiSpec = {
    openapi: '3.0.3',
    info: {
        title: 'API Documentation',
        version: '1.0.0',
        description: `
# API Documentation

A comprehensive API for accessing threat intelligence data including:
- **Vulnerabilities** (CISA KEV, CVE data)
- **IOCs** (Indicators of Compromise)
- **Threat Actors** (MITRE ATT&CK aligned)
- **MITRE ATT&CK** (Tactics, Techniques, Malware, Tools)
- **Pulses** (AlienVault OTX)
- **Real-time Monitoring** (Feed health, system metrics)

## Authentication
All endpoints support the following authentication methods:
- **API Key**: Pass via \`X-API-Key\` header or \`api_key\` query parameter
- **JWT Token**: Pass via \`Authorization: Bearer <token>\` header

## Rate Limiting
- Default: 1000 requests/hour per API key
- Bulk operations: 100 requests/hour
        `,
        contact: {
            name: 'Rinjani Analytics Support',
            email: 'support@rinjanianalytics.com',
        },
        license: {
            name: 'Proprietary',
        },
    },
    servers: [
        { url: 'http://localhost:3001', description: 'Development' },
        { url: 'https://api.rinjanianalytics.com', description: 'Production' },
    ],
    tags: [
        { name: 'Health', description: 'Health check endpoints' },
        { name: 'Auth', description: 'Authentication & authorization' },
        { name: 'Vulnerabilities', description: 'CISA KEV & CVE data' },
        { name: 'IOCs', description: 'Indicators of Compromise' },
        { name: 'Threats', description: 'Threat actors & groups' },
        { name: 'MITRE ATT&CK', description: 'Tactics, Techniques, Malware, Tools' },
        { name: 'Pulses', description: 'AlienVault OTX pulses' },
        { name: 'Search', description: 'Advanced search capabilities' },
        { name: 'Graph Explorer', description: 'Neo4j-powered graph traversal and analysis' },
        { name: 'AI', description: 'AI-powered entity analysis and insights' },
        { name: 'OpenSearch', description: 'Full-text search & index management' },
        { name: 'Export', description: 'Data export (CSV, JSON, STIX)' },
        { name: 'Enrich', description: 'IOC enrichment' },
        { name: 'Monitoring', description: 'Feed health & system metrics' },
        { name: 'Webhooks', description: 'Webhook configuration & management' },
        { name: 'Audit', description: 'Audit logs & entity history' },
        { name: 'Opengate', description: 'API key management' },
        { name: 'Alerts', description: 'Alert management & read status' },
        { name: 'Notifications', description: 'Notification preferences & testing' },
        { name: 'Ops', description: 'Infrastructure health & operational metrics' },
        { name: 'Users', description: 'User CRUD & RBAC management (admin)' },
        { name: 'Admin', description: 'Queue management & job triggers' },
    ],
    components: {
        securitySchemes: {
            apiKey: {
                type: 'apiKey',
                in: 'header',
                name: 'X-API-Key',
                description: 'API key for authentication',
            },
            bearerAuth: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
                description: 'JWT token for authentication',
            },
        },
        schemas,
    },
    security: [{ apiKey: [] }, { bearerAuth: [] }],
    paths: {
        ...pathsV1,
        ...pathsV2,
        ...pathsAdmin,
    },
};
