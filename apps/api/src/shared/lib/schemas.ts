/**
 * Shared Zod Schemas
 *
 * Validated at API ingress (route) and consumed by the worker.
 * Single source of truth for request/response shapes.
 */

import { z } from 'zod';

// ============================================================================
// Web Search — Request & Job Data
// ============================================================================

/**
 * API request body for POST /v1/web-search
 */
export const WebSearchRequestSchema = z.object({
    query: z.string().min(1, 'query is required').max(500),
    numResults: z.number().int().min(1).max(50).default(10),
    provider: z.enum(['searxng', 'exa']).default('searxng'),
    categories: z.array(z.string()).optional(),
    timeRange: z.string().optional(),
    /** If true, persist results to OpenSearch + Neo4j */
    persist: z.boolean().default(false),
    /** If true, extract IOCs from results */
    extractIOCs: z.boolean().default(true),
});

export type WebSearchRequest = z.infer<typeof WebSearchRequestSchema>;

/**
 * Data shape stored in the BullMQ job (superset of the request).
 */
export const WebSearchJobDataSchema = WebSearchRequestSchema.extend({
    /** Unique correlation ID for tracing */
    correlationId: z.string().uuid(),
    /** ISO timestamp when the job was created */
    createdAt: z.string().datetime(),
});

export type WebSearchJobData = z.infer<typeof WebSearchJobDataSchema>;

// ============================================================================
// Web Search — Result
// ============================================================================

export const WebSearchResultItemSchema = z.object({
    title: z.string(),
    url: z.string().url(),
    snippet: z.string().optional(),
    source: z.string().optional(),
    publishedDate: z.string().optional(),
});

export const WebSearchResultSchema = z.object({
    items: z.array(WebSearchResultItemSchema),
    iocs: z.array(z.object({
        type: z.string(),
        value: z.string(),
    })).optional(),
    iocStats: z.record(z.string(), z.number()).optional(),
    provider: z.string(),
    query: z.string(),
    totalResults: z.number().int(),
    /** Persistence outcome (only if persist=true) */
    persisted: z.object({
        opensearch: z.boolean(),
        neo4j: z.boolean(),
    }).optional(),
    processingTimeMs: z.number(),
});

export type WebSearchResult = z.infer<typeof WebSearchResultSchema>;

// ============================================================================
// Job Status Response
// ============================================================================

export const JobStatusResponseSchema = z.object({
    jobId: z.string(),
    status: z.enum(['waiting', 'active', 'completed', 'failed', 'delayed']),
    progress: z.number().min(0).max(100).optional(),
    result: WebSearchResultSchema.optional(),
    error: z.string().optional(),
    createdAt: z.string().optional(),
    completedAt: z.string().optional(),
});

export type JobStatusResponse = z.infer<typeof JobStatusResponseSchema>;

// ============================================================================
// Query Parameter Schemas (shared across route files)
// ============================================================================

/** Maximum page size allowed to prevent unbounded data pulls */
const MAX_PAGE_SIZE = 500;

/** Base pagination for any list endpoint */
export const PaginationSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(25),
});
export type Pagination = z.infer<typeof PaginationSchema>;

/** Pagination + search + sort (most common pattern) */
export const SearchQuerySchema = PaginationSchema.extend({
    q: z.string().optional(),
    sortBy: z.enum(['createdAt', 'updatedAt']).default('createdAt'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
});
export type SearchQuery = z.infer<typeof SearchQuerySchema>;

// ── Entity-specific filter schemas ──────────────────────────────────

export const VulnFilterSchema = SearchQuerySchema.extend({
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    exploited: z.coerce.boolean().optional(),
    ransomware: z.coerce.boolean().optional(),
    vendor: z.string().optional(),
    dateFrom: z.string().optional(), // YYYY-MM-DD
    dateTo: z.string().optional(),
});
export type VulnFilter = z.infer<typeof VulnFilterSchema>;

export const IOCFilterSchema = SearchQuerySchema.extend({
    type: z.string().optional(),       // ip, domain, url, hash, email
    source: z.string().optional(),     // alienvault, abusessl, etc.
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    dateFrom: z.string().optional(),   // YYYY-MM-DD
    dateTo: z.string().optional(),
});
export type IOCFilter = z.infer<typeof IOCFilterSchema>;

export const ThreatActorFilterSchema = SearchQuerySchema.extend({
    country: z.string().optional(),
    motivation: z.string().optional(),
    sophistication: z.string().optional(),
});
export type ThreatActorFilter = z.infer<typeof ThreatActorFilterSchema>;

export const TechniqueFilterSchema = PaginationSchema.extend({
    q: z.string().optional(),
    platform: z.string().optional(),
    tactic: z.string().optional(),
}).transform(d => ({ ...d, pageSize: Math.min(d.pageSize, MAX_PAGE_SIZE) }));

export const UnifiedSearchSchema = SearchQuerySchema.extend({
    type: z.string().optional(), // ioc, vulnerability, threat-actor
});
export type UnifiedSearch = z.infer<typeof UnifiedSearchSchema>;

export const DaysQuerySchema = z.object({
    days: z.coerce.number().int().min(1).max(365).default(30),
});

// ── Graph & Neo4j schemas ───────────────────────────────────────────

/** Graph layout server-side computation params */
export const GraphLayoutSchema = z.object({
    maxIOCs: z.coerce.number().int().min(1).max(100).default(50),
    maxActors: z.coerce.number().int().min(1).max(50).default(30),
    maxCVEs: z.coerce.number().int().min(1).max(50).default(30),
    width: z.coerce.number().int().min(400).max(4000).default(1200),
    height: z.coerce.number().int().min(300).max(3000).default(800),
});

/** Neo4j fuzzy search */
export const Neo4jSearchSchema = z.object({
    q: z.string().min(1, 'Missing search query (?q=...)'),
    limit: z.coerce.number().int().min(1).max(500).default(50),
});

/** Neo4j neighborhood expand */
export const Neo4jExpandSchema = z.object({
    depth: z.coerce.number().int().min(1).max(4).default(1),
    limit: z.coerce.number().int().min(1).max(500).default(100),
});

/** Neo4j shortest path */
export const Neo4jPathSchema = z.object({
    from: z.string().min(1, '"from" is required'),
    to: z.string().min(1, '"to" is required'),
    maxDepth: z.coerce.number().int().min(1).max(10).default(6),
});

/** Vector / similar document search */
export const VectorSearchSchema = z.object({
    q: z.string().min(1, 'Query parameter "q" is required'),
    k: z.coerce.number().int().min(1).max(50).default(10),
    type: z.string().optional(),
});

/** Generic limit param (reusable across routes) */
export const LimitSchema = z.object({
    limit: z.coerce.number().int().min(1).max(10000).default(50),
});

/** Limit + offset pattern (for audit, etc.) */
export const LimitOffsetSchema = z.object({
    limit: z.coerce.number().int().min(1).max(10000).default(50),
    offset: z.coerce.number().int().min(0).default(0),
});

// ── Alert mutation schemas ──────────────────────────────────────────

/** POST /v1/alerts — create a manual alert */
export const CreateAlertSchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
    type: z.string().min(1).max(100).default('system_alert'),
    title: z.string().min(1, 'title is required').max(500),
    message: z.string().min(1, 'message is required').max(5000),
    source: z.string().max(200).optional(),
    metadata: z.record(z.unknown()).optional(),
});
export type CreateAlert = z.infer<typeof CreateAlertSchema>;

/** PUT /v1/alerts/:id — partial update */
export const UpdateAlertSchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    title: z.string().min(1).max(500).optional(),
    message: z.string().min(1).max(5000).optional(),
    metadata: z.record(z.unknown()).optional(),
    read: z.boolean().optional(),
});
export type UpdateAlert = z.infer<typeof UpdateAlertSchema>;

/** POST /v1/alerts/acknowledge — bulk acknowledge */
export const BulkAckSchema = z.object({
    ids: z.array(z.string().uuid()).min(1, 'At least one alert ID is required').max(500),
});
export type BulkAck = z.infer<typeof BulkAckSchema>;

/** POST /v1/alerts/evaluate — threshold for IOC risk evaluation */
export const EvaluateAlertSchema = z.object({
    threshold: z.coerce.number().int().min(1).max(100).default(75),
});
export type EvaluateAlert = z.infer<typeof EvaluateAlertSchema>;

// ── Admin config schemas ────────────────────────────────────────────

/** POST /admin/config/feeds — add a custom feed */
export const AddFeedSchema = z.object({
    name: z.string().min(1).max(200),
    source: z.string().min(1).max(200),
    description: z.string().max(1000).default(''),
    cron: z.string().max(50).default('0 */6 * * *'),
    enabled: z.boolean().default(true),
    category: z.enum(['high-frequency', 'ioc-feeds', 'knowledge-base', 'nexus', 'custom-api', 'rss', 'financial', 'osint']).default('custom-api'),
    url: z.string().url().optional(),
    format: z.enum(['json', 'text', 'rss', 'csv', 'stix']).optional(),
    authHeader: z.string().max(200).optional(),
    authKeyRef: z.string().max(200).optional(),
    requiresApiKey: z.string().max(200).optional(),
});
export type AddFeed = z.infer<typeof AddFeedSchema>;

/** POST /admin/config/api-keys — add a custom API key slot */
export const AddApiKeySchema = z.object({
    name: z.string().min(1).max(200),
    provider: z.string().min(1).max(200),
    envVar: z.string().min(1).max(200),
    value: z.string().optional(),
    testEndpoint: z.string().url().optional(),
    authHeaderName: z.string().max(200).optional(),
});
export type AddApiKey = z.infer<typeof AddApiKeySchema>;

/** POST /admin/config/services — add a custom service */
export const AddServiceSchema = z.object({
    name: z.string().min(1).max(200),
    envVars: z.array(z.object({
        key: z.string().min(1),
        label: z.string().min(1),
        secret: z.boolean().optional(),
    })).min(1, 'At least one envVar required'),
    values: z.record(z.string()).optional(),
});
export type AddService = z.infer<typeof AddServiceSchema>;

/** PUT /admin/config/settings/:key — update a setting value */
export const UpdateSettingSchema = z.object({
    value: z.union([z.string(), z.number(), z.boolean()]),
});
export type UpdateSetting = z.infer<typeof UpdateSettingSchema>;

// ── Federation admin schemas ────────────────────────────────────────

/** POST /admin/federation/tenants — create a new tenant */
export const CreateTenantSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    slug: z.string().min(1, 'slug is required').max(100).regex(/^[a-z0-9-]+$/, 'slug must be lowercase alphanumeric with hyphens'),
    tier: z.enum(['free', 'pro', 'enterprise']).default('free'),
    config: z.record(z.unknown()).optional(),
});
export type CreateTenant = z.infer<typeof CreateTenantSchema>;

/** POST /admin/federation/tenants/:id/peers — add a peer to a tenant */
export const AddPeerSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    url: z.string().url('url must be a valid URL'),
    apiKey: z.string().min(1, 'apiKey is required').max(500),
    trustLevel: z.enum(['full', 'limited', 'read-only']).default('read-only'),
});
export type AddPeer = z.infer<typeof AddPeerSchema>;

/** POST /admin/migrations/rollback — rollback N migrations */
export const RollbackSchema = z.object({
    count: z.coerce.number().int().min(1).max(5).default(1),
});
export type Rollback = z.infer<typeof RollbackSchema>;

/** POST /admin/scoring/rescore — batch rescore IOCs */
export const RescoreSchema = z.object({
    batchSize: z.coerce.number().int().min(1).max(500).default(100),
});
export type Rescore = z.infer<typeof RescoreSchema>;

// ── Notification route schemas ──────────────────────────────────────

/** PUT /notifications/settings — update notification preferences */
export const NotificationSettingsSchema = z.object({
    emailEnabled: z.boolean().optional(),
    emailAddress: z.string().email().nullable().optional(),
    slackEnabled: z.boolean().optional(),
    slackWebhookUrl: z.string().url().nullable().optional(),
    severityThreshold: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    notifyOnNewIOC: z.boolean().optional(),
    notifyOnNewVuln: z.boolean().optional(),
    notifyOnThreatActor: z.boolean().optional(),
});
export type NotificationSettings = z.infer<typeof NotificationSettingsSchema>;

/** POST /notifications/test/slack — test Slack webhook */
export const TestSlackSchema = z.object({
    webhookUrl: z.string().url('webhookUrl must be a valid URL'),
});
export type TestSlack = z.infer<typeof TestSlackSchema>;

/** POST /notifications/test/email — test email delivery */
export const TestEmailSchema = z.object({
    emailAddress: z.string().email('emailAddress must be a valid email'),
});
export type TestEmail = z.infer<typeof TestEmailSchema>;

/** POST /notifications/alert — manually trigger a notification */
export const ManualAlertSchema = z.object({
    type: z.enum(['ioc', 'vulnerability', 'threat_actor', 'alert']),
    severity: z.enum(['critical', 'high', 'medium', 'low']),
    title: z.string().min(1, 'title is required').max(500),
    message: z.string().min(1, 'message is required').max(5000),
    data: z.record(z.unknown()).optional(),
});
export type ManualAlert = z.infer<typeof ManualAlertSchema>;

// ── Playbook route schemas ──────────────────────────────────────────

const PlaybookActionSchema = z.object({
    type: z.enum(['enrich', 'notify', 'alert', 'tag', 'warninglist_check']),
    config: z.record(z.unknown()),
});

/** POST /v1/playbooks — create a new playbook */
export const CreatePlaybookSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    description: z.string().max(2000).optional(),
    triggerEvent: z.string().min(1, 'triggerEvent is required').max(200),
    conditions: z.record(z.unknown()).optional(),
    actions: z.array(PlaybookActionSchema).min(1, 'At least one action is required'),
});
export type CreatePlaybook = z.infer<typeof CreatePlaybookSchema>;

/** PUT /v1/playbooks/:id — partial update */
export const UpdatePlaybookSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(2000).optional(),
    triggerEvent: z.string().min(1).max(200).optional(),
    conditions: z.record(z.unknown()).optional(),
    actions: z.array(PlaybookActionSchema).min(1).optional(),
    enabled: z.boolean().optional(),
});
export type UpdatePlaybook = z.infer<typeof UpdatePlaybookSchema>;

// ── Warninglist route schemas ───────────────────────────────────────

/** POST /v1/warninglists — create a new warninglist */
export const CreateWarninglistSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    type: z.enum(['cidr', 'hostname', 'string', 'regex']),
    description: z.string().max(2000).optional(),
    category: z.string().max(100).optional(),
    source: z.string().max(200).optional(),
    version: z.string().max(50).optional(),
    entries: z.array(z.string()).optional(),
});
export type CreateWarninglist = z.infer<typeof CreateWarninglistSchema>;

/** PUT /v1/warninglists/:id — partial update */
export const UpdateWarninglistSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(2000).optional(),
    category: z.string().max(100).optional(),
    source: z.string().max(200).optional(),
    version: z.string().max(50).optional(),
    enabled: z.boolean().optional(),
});
export type UpdateWarninglist = z.infer<typeof UpdateWarninglistSchema>;

/** POST/DELETE /v1/warninglists/:id/entries — add or remove entries */
export const WarninglistEntriesSchema = z.object({
    values: z.array(z.string()).min(1, 'At least one value is required'),
});
export type WarninglistEntries = z.infer<typeof WarninglistEntriesSchema>;

/** POST /v1/warninglists/check — check a value against warninglists */
export const WarninglistCheckSchema = z.object({
    value: z.string().min(1, 'value is required'),
    type: z.string().max(50).optional(),
});
export type WarninglistCheck = z.infer<typeof WarninglistCheckSchema>;

// ── YARA route schemas ──────────────────────────────────────────────

const YaraStringSchema = z.object({
    id: z.string(),
    value: z.string(),
    type: z.enum(['text', 'hex', 'regex']).default('text'),
    modifiers: z.array(z.string()).default([]),
});

/** POST /v1/yara/rules — add a YARA rule */
export const AddYaraRuleSchema = z.object({
    name: z.string().min(1, 'name is required').regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/, 'name must be alphanumeric with underscores'),
    description: z.string().max(2000).default(''),
    author: z.string().max(200).default('API'),
    tags: z.array(z.string()).default([]),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
    strings: z.array(YaraStringSchema).min(1, 'At least one string pattern is required'),
    condition: z.string().min(1, 'condition is required'),
    enabled: z.boolean().default(true),
});
export type AddYaraRule = z.infer<typeof AddYaraRuleSchema>;

/** PUT /v1/yara/rules/:name/toggle — toggle rule enabled/disabled */
export const ToggleYaraRuleSchema = z.object({
    enabled: z.boolean({ required_error: 'enabled is required' }),
});
export type ToggleYaraRule = z.infer<typeof ToggleYaraRuleSchema>;

/** POST /v1/yara/scan — scan a single value */
export const YaraScanSchema = z.object({
    value: z.string().min(1, 'value is required'),
});
export type YaraScan = z.infer<typeof YaraScanSchema>;

/** POST /v1/yara/batch-scan — scan multiple values */
export const YaraBatchScanSchema = z.object({
    values: z.array(z.string()).min(1, 'At least one value is required').max(10000, 'Maximum 10,000 values per batch'),
});
export type YaraBatchScan = z.infer<typeof YaraBatchScanSchema>;

// ── Playbook execute schema ─────────────────────────────────────────

/** POST /v1/playbooks/:id/execute — manually trigger execution */
export const ExecutePlaybookSchema = z.object({
    triggerData: z.record(z.unknown()).default({}),
});
export type ExecutePlaybook = z.infer<typeof ExecutePlaybookSchema>;

// ── STIX Pipeline schemas ───────────────────────────────────────────

const StixObjectSchema = z.object({
    type: z.string().min(1),
    id: z.string().min(1),
}).passthrough();

/** POST /v1/stix/import — import a STIX 2.1 bundle */
export const StixImportSchema = z.object({
    type: z.literal('bundle'),
    id: z.string().min(1, 'bundle id is required'),
    objects: z.array(StixObjectSchema).max(10000, 'Bundle too large: max 10,000 objects'),
    dryRun: z.boolean().default(false),
}).passthrough();
export type StixImport = z.infer<typeof StixImportSchema>;

/** POST /v1/stix/export — export entities as STIX 2.1 */
export const StixExportSchema = z.object({
    entityTypes: z.array(z.string()).default(['iocs']),
    includeRelationships: z.boolean().default(true),
    limit: z.number().int().min(1).max(5000).default(1000),
});
export type StixExport = z.infer<typeof StixExportSchema>;

// ── User schemas ────────────────────────────────────────────────────

/** POST /users — create a new user */
export const CreateUserSchema = z.object({
    email: z.string().email('Valid email is required'),
    name: z.string().min(1, 'name is required').max(200),
    role: z.enum(['admin', 'analyst', 'viewer']),
});
export type CreateUser = z.infer<typeof CreateUserSchema>;

/** PUT /users/:id — update a user */
export const UpdateUserSchema = z.object({
    email: z.string().email().optional(),
    name: z.string().min(1).max(200).optional(),
    role: z.enum(['admin', 'analyst', 'viewer']).optional(),
    status: z.enum(['active', 'inactive', 'pending']).optional(),
});
export type UpdateUser = z.infer<typeof UpdateUserSchema>;

// ── Sighting schema ─────────────────────────────────────────────────

/** POST /v1/iocs/:iocId/sightings — report a sighting */
export const AddSightingSchema = z.object({
    source: z.string().min(1, 'source is required').max(200),
    type: z.enum(['sighting', 'false-positive', 'expiration']).optional(),
    description: z.string().max(2000).optional(),
    confidence: z.number().min(0).max(100).optional(),
    count: z.number().int().min(1).optional(),
    observedAt: z.string().datetime().optional(),
});
export type AddSighting = z.infer<typeof AddSightingSchema>;

// ── Config update schemas ───────────────────────────────────────────

/** PUT /config/api-keys/:id — update API key value */
export const UpdateApiKeyValueSchema = z.object({
    value: z.string().min(1, 'API key value is required'),
});
export type UpdateApiKeyValue = z.infer<typeof UpdateApiKeyValueSchema>;

/** PUT /config/services/:id — update service env vars */
export const UpdateServiceSchema = z.object({}).passthrough();
export type UpdateService = z.infer<typeof UpdateServiceSchema>;

/** PUT /config/feeds/:id — update a feed */
export const UpdateFeedSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    source: z.string().max(200).optional(),
    description: z.string().max(1000).optional(),
    cron: z.string().max(50).optional(),
    enabled: z.boolean().optional(),
    category: z.string().max(100).optional(),
    url: z.string().url().optional(),
    format: z.enum(['json', 'text', 'rss', 'csv', 'stix']).optional(),
    authHeader: z.string().max(200).optional(),
    authKeyRef: z.string().max(200).optional(),
});
export type UpdateFeed = z.infer<typeof UpdateFeedSchema>;

// ============================================================================
// Phase T — Graph, Export, TAXII, Enrich, Streaming Schemas
// ============================================================================

/** POST /v1/graph/neo4j/sync — Trigger a Neo4j sync job */
export const Neo4jSyncSchema = z.object({
    syncType: z.enum(['full', 'incremental', 'iocs', 'all-iocs', 'actors', 'cves', 'techniques', 'malware', 'tools', 'relationships', 'pulses-iocs', 'similarity']).default('full'),
    options: z.record(z.unknown()).default({}),
});
export type Neo4jSync = z.infer<typeof Neo4jSyncSchema>;

/** POST /v1/graph/neo4j/cypher — Execute a read-only Cypher query */
export const CypherQuerySchema = z.object({
    query: z.string().min(1, 'query is required').max(5000),
    params: z.record(z.unknown()).optional(),
    limit: z.number().int().min(1).max(1000).default(100),
});
export type CypherQuery = z.infer<typeof CypherQuerySchema>;

/** Shared schema for all export POST routes (csv, json, stix) */
export const ExportRequestSchema = z.object({
    filters: z.record(z.unknown()).default({}),
    limit: z.number().int().min(1).max(50000).default(10000),
});
export type ExportRequest = z.infer<typeof ExportRequestSchema>;

/** POST /taxii2/collections/:id/objects/ — Inbound STIX bundle ingestion */
export const TaxiiInboundSchema = z.object({
    type: z.literal('bundle', { errorMap: () => ({ message: 'Request body must be a valid STIX 2.1 bundle' }) }),
    objects: z.array(z.record(z.unknown())).max(10000, 'Bundle exceeds maximum 10,000 objects'),
}).passthrough();
export type TaxiiInbound = z.infer<typeof TaxiiInboundSchema>;

/** POST /v1/enrich/bulk — Bulk enrichment for multiple IOCs */
export const BulkEnrichSchema = z.object({
    values: z.array(z.string()).min(1, 'Values array is required').max(100, 'Maximum 100 values per request'),
});
export type BulkEnrich = z.infer<typeof BulkEnrichSchema>;

/** POST /v2/stream/subscribe — Create a filtered subscription */
export const StreamSubscribeSchema = z.object({
    channels: z.array(z.string()).default(['webint']),
    keywords: z.array(z.string()).default([]),
});
export type StreamSubscribe = z.infer<typeof StreamSubscribeSchema>;

// ============================================================================
// Phase W — Opengate, Webhooks, Admin Users/Jobs/Sandbox Schemas
// ============================================================================

/** POST /opengate/keys — Create an API key */
export const CreateApiKeySchema = z.object({
    name: z.string().min(1).max(100).default('API Key'),
});
export type CreateApiKey = z.infer<typeof CreateApiKeySchema>;

/** POST /v1/webhooks — Register a webhook subscription */
export const CreateWebhookSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    url: z.string().url('Invalid URL format'),
    secret: z.string().optional(),
    events: z.array(z.string()).default(['*']),
    filters: z.object({
        severity: z.array(z.string()).optional(),
        type: z.array(z.string()).optional(),
        source: z.array(z.string()).optional(),
    }).default({}),
    headers: z.record(z.string()).default({}),
});
export type CreateWebhook = z.infer<typeof CreateWebhookSchema>;

/** POST /admin/users — Create a user */
export const AdminCreateUserSchema = z.object({
    email: z.string().email('Valid email is required'),
    name: z.string().min(1, 'name is required').max(200),
    role: z.string().min(1, 'role is required'),
    permissions: z.array(z.string()).optional(),
});
export type AdminCreateUser = z.infer<typeof AdminCreateUserSchema>;

/** PUT /admin/users/:id — Update a user */
export const AdminUpdateUserSchema = z.object({
    email: z.string().email().optional(),
    name: z.string().min(1).max(200).optional(),
    role: z.string().min(1).optional(),
    permissions: z.array(z.string()).optional(),
    isActive: z.boolean().optional(),
});
export type AdminUpdateUser = z.infer<typeof AdminUpdateUserSchema>;

/** POST /admin/users/roles — Create a role */
export const AdminCreateRoleSchema = z.object({
    id: z.string().min(1, 'id is required').max(50),
    name: z.string().min(1, 'name is required').max(200),
    description: z.string().default(''),
    defaultPermissions: z.array(z.string()).default([]),
});
export type AdminCreateRole = z.infer<typeof AdminCreateRoleSchema>;

/** PUT /admin/users/roles/:id — Update a role */
export const AdminUpdateRoleSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().optional(),
    defaultPermissions: z.array(z.string()).optional(),
});
export type AdminUpdateRole = z.infer<typeof AdminUpdateRoleSchema>;

/** POST /admin/users/permissions — Create a permission module */
export const AdminCreatePermModuleSchema = z.object({
    id: z.string().min(1, 'id is required').max(50),
    name: z.string().min(1, 'name is required').max(200),
    icon: z.string().default('settings'),
    permissions: z.array(z.object({
        id: z.string().min(1),
        name: z.string().min(1),
        description: z.string(),
    })).default([]),
});
export type AdminCreatePermModule = z.infer<typeof AdminCreatePermModuleSchema>;

/** PUT /admin/users/permissions/:id — Update a permission module */
export const AdminUpdatePermModuleSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    icon: z.string().optional(),
    permissions: z.array(z.object({
        id: z.string().min(1),
        name: z.string().min(1),
        description: z.string(),
    })).optional(),
});
export type AdminUpdatePermModule = z.infer<typeof AdminUpdatePermModuleSchema>;

/** POST /admin/jobs/feed-sync — Trigger a feed sync job */
export const FeedSyncJobSchema = z.object({
    source: z.string().default('all'),
    options: z.record(z.unknown()).optional(),
});
export type FeedSyncJob = z.infer<typeof FeedSyncJobSchema>;

/** POST /admin/jobs/enrichment — Queue IOC enrichment */
export const EnrichmentJobSchema = z.object({
    iocId: z.string().min(1, 'iocId is required'),
    iocValue: z.string().min(1, 'iocValue is required'),
    iocType: z.string().min(1, 'iocType is required'),
    sources: z.array(z.string()).optional(),
});
export type EnrichmentJob = z.infer<typeof EnrichmentJobSchema>;

/** POST /admin/jobs/ai-analysis — Queue AI analysis */
export const AiAnalysisJobSchema = z.object({
    iocId: z.string().min(1, 'iocId is required'),
    iocValue: z.string().min(1, 'iocValue is required'),
    analysisType: z.string().default('threat-assessment'),
});
export type AiAnalysisJob = z.infer<typeof AiAnalysisJobSchema>;

/** POST /admin/jobs/notification — Queue a notification */
export const NotificationJobQueueSchema = z.object({
    channel: z.string().min(1, 'channel is required'),
    target: z.string().min(1, 'target is required'),
    payload: z.record(z.unknown()),
});
export type NotificationJobQueue = z.infer<typeof NotificationJobQueueSchema>;

/** POST /admin/jobs/neo4j-sync — Trigger Neo4j sync */
export const Neo4jSyncJobSchema = z.object({
    syncType: z.string().default('all-iocs'),
    options: z.record(z.unknown()).optional(),
});
export type Neo4jSyncJob = z.infer<typeof Neo4jSyncJobSchema>;

/** POST /admin/sandbox/test-feed — Test feed connectivity */
export const SandboxTestFeedSchema = z.object({
    url: z.string().url('Invalid URL format'),
    authHeader: z.string().optional(),
    authValue: z.string().optional(),
    authType: z.enum(['header', 'query']).optional(),
    authParam: z.string().optional(),
    method: z.enum(['GET', 'POST', 'HEAD', 'get', 'post', 'head']).default('GET'),
});
export type SandboxTestFeed = z.infer<typeof SandboxTestFeedSchema>;

/** POST /admin/sandbox/test-endpoint — Test arbitrary endpoint */
export const SandboxTestEndpointSchema = z.object({
    url: z.string().url('Invalid URL format'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD',
        'get', 'post', 'put', 'delete', 'patch', 'head']).default('GET'),
    headers: z.record(z.string()).optional(),
    body: z.unknown().optional(),
    timeoutMs: z.number().int().min(1000).max(30000).default(10000),
});
export type SandboxTestEndpoint = z.infer<typeof SandboxTestEndpointSchema>;

// ============================================================================
// Phase Y — Remaining Route Validation Schemas
// ============================================================================

/** POST /v1/correlation/batch — batch correlation limit */
export const BatchCorrelationSchema = z.object({
    limit: z.coerce.number().int().min(1).max(5000).default(500),
});
export type BatchCorrelation = z.infer<typeof BatchCorrelationSchema>;

/** GET /v1/iocs/:iocId/sightings — list sightings */
export const SightingListSchema = z.object({
    limit: z.coerce.number().int().min(1).max(500).default(50),
    offset: z.coerce.number().int().min(0).default(0),
});
export type SightingList = z.infer<typeof SightingListSchema>;

/** GET /v1/sightings/feed — sighting feed with optional iocId filter */
export const SightingFeedSchema = z.object({
    limit: z.coerce.number().int().min(1).max(500).default(50),
    iocId: z.string().optional(),
});
export type SightingFeed = z.infer<typeof SightingFeedSchema>;

/** GET /v1/alerts — alert list filters */
export const AlertListFilterSchema = PaginationSchema.extend({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    unread: z.coerce.boolean().optional(),
});
export type AlertListFilter = z.infer<typeof AlertListFilterSchema>;

/** GET /v1/audit — audit log filters */
export const AuditFilterSchema = LimitOffsetSchema.extend({
    entityType: z.string().optional(),
    entityId: z.string().optional(),
    action: z.string().optional(),
    source: z.string().optional(),
});
export type AuditFilter = z.infer<typeof AuditFilterSchema>;

/** GET /v2/stix/bundle — STIX bundle export filters */
export const StixBundleQuerySchema = LimitSchema.extend({
    include: z.string().optional(),
    type: z.string().optional(),
    source: z.string().optional(),
    severity: z.string().optional(),
});
export type StixBundleQuery = z.infer<typeof StixBundleQuerySchema>;

/** GET /taxii2/collections/:id/objects/ — TAXII envelope query */
export const TaxiiEnvelopeQuerySchema = z.object({
    added_after: z.string().optional(),
    limit: z.coerce.number().int().min(1).max(1000).default(100),
    next: z.string().optional(),
    'match[type]': z.string().optional(),
    'match[id]': z.string().optional(),
});
export type TaxiiEnvelopeQuery = z.infer<typeof TaxiiEnvelopeQuerySchema>;

/** GET /intelligence/ioc/:value — intelligence query params */
export const IntelligenceIOCQuerySchema = z.object({
    refresh: z.coerce.boolean().default(false),
    sources: z.string().optional(),
});
export type IntelligenceIOCQuery = z.infer<typeof IntelligenceIOCQuerySchema>;

// ============================================================================
// Phase Z — Final Validation Sweep Schemas
// ============================================================================

/** GET /admin/audit — paginated, filterable audit log list */
export const AdminAuditListSchema = z.object({
    entityType: z.enum(['ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware']).optional(),
    action: z.string().optional(),
    from: z.string().optional(),
    to: z.string().optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(50),
});
export type AdminAuditList = z.infer<typeof AdminAuditListSchema>;

/** GET /admin/audit/stats — audit stats time range */
export const AdminAuditStatsSchema = z.object({
    days: z.coerce.number().int().min(1).max(365).default(30),
});
export type AdminAuditStats = z.infer<typeof AdminAuditStatsSchema>;

/** GET /admin/users — filterable user list */
export const AdminUserListSchema = z.object({
    role: z.string().optional(),
    status: z.enum(['active', 'inactive', 'all']).optional(),
    search: z.string().optional(),
    page: z.coerce.number().int().min(1).optional(),
    limit: z.coerce.number().int().min(1).max(100).optional(),
});
export type AdminUserList = z.infer<typeof AdminUserListSchema>;

/** POST /admin/queue/:name/clean/:state — queue clean params */
export const AdminQueueCleanSchema = z.object({
    grace: z.coerce.number().int().min(0).default(0),
    limit: z.coerce.number().int().min(1).max(10000).default(1000),
});
export type AdminQueueClean = z.infer<typeof AdminQueueCleanSchema>;

/** GET /admin/queue/:name/jobs — queue job listing params */
export const AdminQueueJobsSchema = z.object({
    state: z.enum(['waiting', 'active', 'completed', 'failed', 'delayed']).default('failed'),
    start: z.coerce.number().int().min(0).default(0),
    limit: z.coerce.number().int().min(1).max(500).default(20),
});
export type AdminQueueJobs = z.infer<typeof AdminQueueJobsSchema>;

/** GET /admin/dlq — DLQ pagination */
export const AdminDLQListSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(50),
});
export type AdminDLQList = z.infer<typeof AdminDLQListSchema>;

/** POST /admin/streams/:stream/claim — stream claim query params */
export const AdminStreamClaimSchema = z.object({
    group: z.string().default('enrichment-group'),
    consumer: z.string().default('claimer'),
    minIdleMs: z.coerce.number().int().min(0).default(60000),
});
export type AdminStreamClaim = z.infer<typeof AdminStreamClaimSchema>;

/** GET /users — in-memory user list filters */
export const UserListQuerySchema = z.object({
    status: z.string().optional(),
    role: z.string().optional(),
});
export type UserListQuery = z.infer<typeof UserListQuerySchema>;

/** GET /export/iocs — bulk export format */
export const BulkExportQuerySchema = z.object({
    format: z.enum(['json', 'csv', 'stix']).default('json'),
});
export type BulkExportQuery = z.infer<typeof BulkExportQuerySchema>;

/** GET /monitoring/metrics/growth — granularity param */
export const MetricsGrowthQuerySchema = z.object({
    granularity: z.enum(['day', 'hour']).default('day'),
});
export type MetricsGrowthQuery = z.infer<typeof MetricsGrowthQuerySchema>;

// ============================================================================
// Phase AA — AI Analysis Body Schema
// ============================================================================

/** POST /v2/ai/analyze — AI entity analysis request body */
export const AIAnalyzeSchema = z.object({
    entityType: z.enum(['ioc', 'cve', 'actor']),
    entityId: z.string().min(1, 'entityId is required'),
    entityData: z.record(z.unknown()),
    forceRefresh: z.boolean().default(false),
});
export type AIAnalyze = z.infer<typeof AIAnalyzeSchema>;

/** POST /v2/events/publish — SSE event publish body */
export const SSEPublishSchema = z.object({
    channel: z.enum(['ioc', 'alert', 'feed', 'enrichment', 'system']),
    type: z.string().min(1, 'type is required'),
    data: z.record(z.unknown()),
    source: z.string().optional(),
});
export type SSEPublish = z.infer<typeof SSEPublishSchema>;

