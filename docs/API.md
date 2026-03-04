# Rinjani CTI Platform — API Reference

> Auto-generated reference for v3 backend. Base URL: `http://localhost:3001`
>
> **Authentication**: Most endpoints require `X-API-Key` header or Bearer token.
> Role-restricted endpoints are marked with 🔒 followed by required role(s).

---

## Health & Discovery

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/health` | Service health with dependency status |
| `GET` | `/` | API info & version |
| `GET` | `/api-docs` | Interactive API docs |
| `GET` | `/api-docs/openapi.json` | OpenAPI spec |

---

## V1 — Core Intelligence

### IOCs

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/iocs` | ✓ | List IOCs (offset pagination) |
| `GET` | `/v1/iocs/cursor` | ✓ | List IOCs (cursor pagination) |
| `GET` | `/v1/iocs/:idOrValue` | ✓ | Get IOC by ID or value |

### Vulnerabilities (CVEs)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/vulnerabilities` | ✓ | List CVEs (offset pagination) |
| `GET` | `/v1/vulnerabilities/cursor` | ✓ | List CVEs (cursor pagination) |
| `GET` | `/v1/vulnerabilities/:cveId` | ✓ | Get CVE by ID |

### Threats & Actors

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/threats` | ✓ | List threat actors |
| `GET` | `/v1/threats/:id` | ✓ | Get threat actor by ID |
| `GET` | `/v1/threats/cursor` | ✓ | Cursor-paginated threats |
| `GET` | `/v1/pulses` | ✓ | List threat pulses |
| `GET` | `/v1/pulses/cursor` | ✓ | Cursor-paginated pulses |
| `GET` | `/v1/indicators` | ✓ | List indicators |
| `GET` | `/v1/indicators/cursor` | ✓ | Cursor-paginated indicators |

### Intelligence (Enriched Detail)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/intelligence/ioc/:value` | ✓ | Full IOC intelligence report |
| `GET` | `/v1/intelligence/cve/:cveId` | ✓ | Full CVE intelligence report |
| `GET` | `/v1/intelligence/actor/:id` | ✓ | Full actor intelligence report |

### Sightings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/iocs/:iocId/sightings` | ✓ | Record a sighting |
| `GET` | `/v1/iocs/:iocId/sightings` | ✓ | List sightings for IOC |
| `GET` | `/v1/sightings/recent` | ✓ | Recent sightings across all IOCs |

### Correlation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/iocs/:iocId/correlate` | ✓ | Trigger correlation analysis |
| `GET` | `/v1/iocs/:iocId/correlations` | ✓ | Get IOC correlations |
| `POST` | `/v1/correlation/batch` | 🔒 admin | Batch correlation run |

---

## V1 — Search

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/search` | ✓ | Unified search (OpenSearch) |
| `GET` | `/v1/search/vector` | ✓ | Vector/semantic search |
| `GET` | `/v1/search/similar/:docId` | ✓ | Find similar documents |
| `GET` | `/v1/search/instant` | ✓ | MeiliSearch instant search |
| `GET` | `/v1/search/instant/stats` | ✓ | MeiliSearch index stats |
| `POST` | `/v1/search/instant/reindex` | ✓ | Trigger MeiliSearch reindex |

---

## V1 — Statistics & Monitoring

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/stats` | ✓ | Overview counts |
| `GET` | `/v1/stats/distribution` | ✓ | Type distribution |
| `GET` | `/v1/stats/severity-trend` | ✓ | Severity over time |
| `GET` | `/v1/stats/source-breakdown` | ✓ | Source attribution |
| `GET` | `/v1/stats/threat-heatmap` | ✓ | Threat activity heatmap |
| `GET` | `/v1/stats/freshness` | ✓ | Data freshness metrics |
| `GET` | `/v1/tactics` | ✓ | MITRE tactic distribution |
| `GET` | `/v1/monitoring/feeds` | ✓ | Feed ingestion status |
| `GET` | `/v1/monitoring/health` | ✓ | System health dashboard |

---

## V1 — MITRE ATT&CK

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/techniques` | ✓ | List techniques |
| `GET` | `/v1/techniques/:mitreId` | ✓ | Technique detail |
| `GET` | `/v1/threat-actors` | ✓ | MITRE threat actors |
| `GET` | `/v1/malware` | ✓ | MITRE malware catalog |
| `GET` | `/v1/tools` | ✓ | MITRE tools catalog |
| `GET` | `/v1/mitre/matrix` | ✓ | Full ATT&CK matrix |

---

## V1 — Graph (Neo4j)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/graph/layout` | ✓ | Server-side graph layout (d3-force SSR) |
| `GET` | `/v1/graph/neo4j/health` | ✓ | Neo4j health check |
| `GET` | `/v1/graph/neo4j/stats` | ✓ | Node/relationship counts |
| `POST` | `/v1/graph/neo4j/sync` | ✓ | Sync entities to Neo4j |
| `GET` | `/v1/graph/neo4j/search` | ✓ | Graph text search |
| `GET` | `/v1/graph/neo4j/expand/:nodeId` | ✓ | Expand node neighbors |
| `GET` | `/v1/graph/neo4j/path` | ✓ | Shortest path between nodes |
| `GET` | `/v1/graph/neo4j/attack-tree/:actor` | ✓ | Actor attack tree |
| `GET` | `/v1/graph/neo4j/ioc-pivot/:iocValue` | ✓ | IOC pivot analysis |
| `GET` | `/v1/graph/neo4j/related-actors/:actor` | ✓ | Related actors graph |
| `POST` | `/v1/graph/neo4j/cypher` | ✓ | Raw Cypher query |
| `POST` | `/v1/graph/neo4j/backfill-mentions` | ✓ | Backfill IOC mentions |

---

## V1 — Configuration

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/config/feeds` | ✓ | List feeds |
| `POST` | `/v1/config/feeds` | ✓ | Create feed |
| `PUT` | `/v1/config/feeds/:id` | ✓ | Update feed |
| `DELETE` | `/v1/config/feeds/:id` | ✓ | Delete feed |
| `GET` | `/v1/config/api-keys` | ✓ | List API keys |
| `POST` | `/v1/config/api-keys` | ✓ | Create API key |
| `PUT` | `/v1/config/api-keys/:id` | ✓ | Update API key |
| `DELETE` | `/v1/config/api-keys/:id` | ✓ | Delete API key |
| `POST` | `/v1/config/api-keys/:id/test` | ✓ | Test API key connectivity |
| `GET` | `/v1/config/services` | ✓ | List services |
| `POST` | `/v1/config/services` | ✓ | Create service |
| `PUT` | `/v1/config/services/:id` | ✓ | Update service |
| `DELETE` | `/v1/config/services/:id` | ✓ | Delete service |
| `GET` | `/v1/config/integrations` | ✓ | All integrations summary |

---

## V1 — Batch Operations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/batch/iocs/update` | 🔒 admin, analyst | Bulk update IOCs |
| `POST` | `/v1/batch/iocs/delete` | 🔒 admin | Bulk delete IOCs |
| `POST` | `/v1/batch/iocs/purge` | 🔒 admin | Purge IOCs by filter |
| `POST` | `/v1/batch/iocs/tags` | 🔒 admin, analyst | Bulk tag IOCs |
| `POST` | `/v1/batch/cves/update` | 🔒 admin, analyst | Bulk update CVEs |
| `POST` | `/v1/batch/cves/delete` | 🔒 admin | Bulk delete CVEs |

---

## V1 — Playbooks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/playbooks` | ✓ | List playbooks |
| `POST` | `/v1/playbooks` | 🔒 admin, analyst | Create playbook |
| `GET` | `/v1/playbooks/:id` | ✓ | Get playbook |
| `PUT` | `/v1/playbooks/:id` | 🔒 admin, analyst | Update playbook |
| `DELETE` | `/v1/playbooks/:id` | 🔒 admin | Delete playbook |
| `POST` | `/v1/playbooks/:id/execute` | 🔒 admin, analyst | Execute playbook |
| `GET` | `/v1/playbooks/:id/executions` | ✓ | Execution history |

---

## V1 — STIX Pipeline

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/stix/import` | 🔒 analyst | Import STIX bundle |
| `POST` | `/v1/stix/export` | ✓ | Export as STIX |
| `POST` | `/v1/stix/validate` | ✓ | Validate STIX bundle |

---

## V1 — YARA Rules

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/yara/rules` | ✓ | List YARA rules |
| `GET` | `/v1/yara/rules/:name` | ✓ | Get rule by name |
| `POST` | `/v1/yara/rules` | 🔒 admin | Create rule |
| `PUT` | `/v1/yara/rules/:name/toggle` | 🔒 admin | Enable/disable rule |
| `DELETE` | `/v1/yara/rules/:name` | 🔒 admin | Delete rule |
| `POST` | `/v1/yara/scan` | ✓ | Scan text with rules |
| `POST` | `/v1/yara/batch-scan` | ✓ | Batch scan |

---

## V1 — Warning Lists

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/warninglists` | ✓ | List warning lists |
| `POST` | `/v1/warninglists` | 🔒 admin | Create list |
| `GET` | `/v1/warninglists/:id` | ✓ | Get list |
| `PUT` | `/v1/warninglists/:id` | 🔒 admin | Update list |
| `DELETE` | `/v1/warninglists/:id` | 🔒 admin | Delete list |
| `POST` | `/v1/warninglists/:id/entries` | 🔒 admin, analyst | Add entries |
| `DELETE` | `/v1/warninglists/:id/entries` | 🔒 admin, analyst | Remove entries |
| `POST` | `/v1/warninglists/check` | ✓ | Check value against lists |
| `POST` | `/v1/warninglists/seed` | 🔒 admin | Seed default lists |

---

## V1 — n8n Integration

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/n8n/workflows` | ✓ | List n8n workflows |
| `GET` | `/v1/n8n/executions` | ✓ | List executions |
| `GET` | `/v1/n8n/status` | ✓ | n8n instance status |
| `POST` | `/v1/n8n/trigger/:webhook` | ✓ | Trigger webhook |

---

## V2 — Advanced

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v2/search` | ✓ | Advanced OpenSearch query |
| `POST` | `/v2/search/reindex` | 🔒 admin | Full reindex |
| `POST` | `/v2/search/init` | 🔒 admin | Initialize search index |
| `POST` | `/v2/search/recreate` | 🔒 admin | Recreate index from scratch |
| `POST` | `/v2/threats/lookup` | ✓ | Threat indicator lookup |
| `POST` | `/v2/ai/analyze` | ✓ | AI-powered analysis |

---

## SSE — Real-Time Events

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v2/events` | — | SSE event stream |
| `POST` | `/v2/events/publish` | ✓ | Publish event |
| `GET` | `/v2/events/channels` | ✓ | List available channels |

---

## STIX/TAXII

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/stix/` | — | STIX discovery |
| `GET` | `/stix/bundle` | ✓ | Get STIX bundle |
| `GET` | `/stix/indicator/:id` | ✓ | STIX indicator |
| `GET` | `/stix/threat-actor/:id` | ✓ | STIX threat actor |
| `GET` | `/stix/vulnerability/:id` | ✓ | STIX vulnerability |
| `GET` | `/taxii/` | — | TAXII discovery |
| `GET` | `/taxii/collections/` | — | List collections |
| `GET` | `/taxii/collections/:id` | — | Collection info |
| `GET` | `/taxii/collections/:id/objects/` | 🔒 taxii | Get objects |
| `POST` | `/taxii/collections/:id/objects/` | 🔒 taxii | Add objects |
| `GET` | `/taxii/collections/:id/manifest/` | 🔒 taxii | Object manifest |

---

## Enrichment

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/enrich/ip/:ip` | ✓ | Enrich IP address |
| `GET` | `/enrich/domain/:domain` | ✓ | Enrich domain |
| `GET` | `/enrich/hash/:hash` | ✓ | Enrich file hash |
| `POST` | `/enrich/bulk` | ✓ | Bulk enrichment |

---

## Export

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/export/iocs/csv` | ✓ | Export IOCs as CSV |
| `POST` | `/export/vulnerabilities/csv` | ✓ | Export CVEs as CSV |
| `POST` | `/export/iocs/json` | ✓ | Export IOCs as JSON |
| `POST` | `/export/vulnerabilities/json` | ✓ | Export CVEs as JSON |
| `POST` | `/export/iocs/stix` | ✓ | Export IOCs as STIX |

---

## Nexus (Web Intelligence)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/nexus/search` | ✓ | Web search via SearXNG |
| `POST` | `/nexus/search/threats` | ✓ | Threat-focused web search |
| `POST` | `/nexus/extract-iocs` | ✓ | Extract IOCs from text |
| `POST` | `/nexus/websets` | ✓ | Create Exa webset |
| `POST` | `/nexus/websets/:id/sync` | ✓ | Sync webset |
| `DELETE` | `/nexus/websets/:id` | ✓ | Delete webset |
| `POST` | `/nexus/webhook` | ✓ | Exa webhook receiver |
| `POST` | `/nexus/bootstrap` | ✓ | Bootstrap websets |
| `POST` | `/nexus/bootstrap/monitors` | ✓ | Bootstrap monitors |

---

## Alerts & Notifications

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/alerts` | ✓ | List alerts |
| `GET` | `/alerts/unread/count` | ✓ | Unread count |
| `POST` | `/alerts/:id/read` | ✓ | Mark read |
| `POST` | `/alerts/read-all` | ✓ | Mark all read |
| `POST` | `/alerts` | ✓ | Create alert rule |
| `PUT` | `/alerts/:id` | ✓ | Update alert rule |
| `DELETE` | `/alerts/:id` | ✓ | Delete alert rule |
| `POST` | `/alerts/:id/acknowledge` | ✓ | Acknowledge alert |
| `POST` | `/alerts/evaluate` | ✓ | Evaluate alert rules |
| `GET` | `/notifications` | ✓ | List notifications |
| `GET` | `/notifications/unread-count` | ✓ | Unread notification count |
| `POST` | `/notifications/mark-read` | ✓ | Mark notifications read |
| `GET` | `/notifications/settings` | ✓ | Notification settings |
| `PUT` | `/notifications/settings` | ✓ | Update notification settings |
| `POST` | `/notifications/test/slack` | ✓ | Test Slack notification |
| `POST` | `/notifications/test/email` | ✓ | Test email notification |
| `POST` | `/notifications/alert` | ✓ | Send alert notification |
| `GET` | `/notifications/history` | ✓ | Notification history |

---

## Graph (Legacy)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/graph/expand/:id` | ✓ | Expand node |
| `GET` | `/graph/path` | ✓ | Find path |
| `GET` | `/graph/attack-tree/:actor` | ✓ | Attack tree |
| `GET` | `/graph/ioc-pivot/:value` | ✓ | IOC pivot |
| `GET` | `/graph/related-actors/:actor` | ✓ | Related actors |
| `GET` | `/graph/campaigns` | ✓ | Campaign graph |
| `GET` | `/graph/source-influence` | ✓ | Source influence |
| `GET` | `/graph/attribution/:ioc` | ✓ | IOC attribution |
| `POST` | `/graph/cypher` | 🔒 admin | Raw Cypher |

---

## Webhooks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/webhooks` | ✓ | List webhooks |
| `GET` | `/webhooks/:id` | ✓ | Get webhook |
| `POST` | `/webhooks` | 🔒 admin, analyst | Create webhook |
| `DELETE` | `/webhooks/:id` | 🔒 admin | Delete webhook |
| `POST` | `/webhooks/:id/test` | 🔒 admin, analyst | Test webhook |
| `GET` | `/webhooks/events` | ✓ | Supported events |

---

## Admin — User Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/users` | 🔒 admin | List users |
| `GET` | `/admin/users/:id` | 🔒 admin | Get user |
| `POST` | `/admin/users` | 🔒 admin | Create user |
| `PUT` | `/admin/users/:id` | 🔒 admin | Update user |
| `DELETE` | `/admin/users/:id` | 🔒 admin | Delete user |
| `POST` | `/admin/users/:id/activate` | 🔒 admin | Activate user |
| `POST` | `/admin/users/:id/deactivate` | 🔒 admin | Deactivate user |
| `POST` | `/admin/users/:id/regenerate-token` | 🔒 admin | Regenerate token |
| `GET` | `/admin/users/roles/list` | 🔒 admin | List roles |
| `POST` | `/admin/users/roles` | 🔒 admin | Create role |
| `PUT` | `/admin/users/roles/:id` | 🔒 admin | Update role |
| `DELETE` | `/admin/users/roles/:id` | 🔒 admin | Delete role |
| `POST` | `/admin/users/permissions` | 🔒 admin | Create permission |
| `PUT` | `/admin/users/permissions/:id` | 🔒 admin | Update permission |
| `DELETE` | `/admin/users/permissions/:id` | 🔒 admin | Delete permission |

---

## Admin — RBAC

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/policies` | 🔒 admin | RBAC policies |
| `GET` | `/admin/matrix` | 🔒 admin | Permission matrix |
| `GET` | `/admin/roles` | 🔒 admin | Roles list |
| `GET` | `/admin/roles/:id` | 🔒 admin | Role detail |
| `PUT` | `/admin/roles/:id/permissions` | 🔒 admin | Update role permissions |
| `GET` | `/admin/keycloak/mapping` | 🔒 admin | Keycloak role mapping |
| `PUT` | `/admin/keycloak/mapping` | 🔒 admin | Update Keycloak mapping |
| `POST` | `/admin/keycloak/sync` | 🔒 admin | Sync with Keycloak |
| `GET` | `/admin/summary` | 🔒 admin | RBAC summary |

---

## Admin — Jobs & Queues

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/admin/jobs/feed-sync` | 🔒 admin, analyst | Trigger feed sync |
| `POST` | `/admin/jobs/enrichment` | 🔒 admin, analyst | Trigger enrichment job |
| `POST` | `/admin/jobs/ai-analysis` | 🔒 admin, analyst | Trigger AI analysis |
| `POST` | `/admin/jobs/notification` | 🔒 admin, analyst | Trigger notification job |
| `POST` | `/admin/jobs/neo4j-sync` | 🔒 admin, analyst | Trigger Neo4j sync |
| `GET` | `/admin/jobs/:queue/:jobId` | ✓ | Get job status |
| `GET` | `/admin/stats` | ✓ | Queue statistics |
| `POST` | `/admin/queue/:name/pause` | 🔒 admin | Pause queue |
| `POST` | `/admin/queue/:name/resume` | 🔒 admin | Resume queue |

---

## Admin — DLQ (Dead Letter Queue)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/dlq` | 🔒 admin | List DLQ messages |
| `GET` | `/admin/dlq/stats` | 🔒 admin | DLQ statistics |
| `POST` | `/admin/dlq/:id/replay` | 🔒 admin | Replay message |
| `DELETE` | `/admin/dlq/:id` | 🔒 admin | Delete message |
| `DELETE` | `/admin/dlq/purge` | 🔒 admin | Purge all DLQ |

---

## Admin — Audit

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/audit` | 🔒 admin, auditor | List audit logs |
| `GET` | `/admin/audit/stats` | 🔒 admin, auditor | Audit statistics |
| `GET` | `/admin/audit/:id` | 🔒 admin, auditor | Get audit entry |

---

## Admin — Federation & Scoring

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/federation/stats` | 🔒 admin | Federation stats |
| `GET` | `/admin/federation/tenants` | 🔒 admin | List tenants |
| `POST` | `/admin/federation/tenants` | 🔒 admin | Create tenant |
| `GET` | `/admin/federation/tenants/:id` | 🔒 admin | Get tenant |
| `POST` | `/admin/federation/tenants/:id/suspend` | 🔒 admin | Suspend tenant |
| `POST` | `/admin/federation/tenants/:id/reactivate` | 🔒 admin | Reactivate tenant |
| `GET` | `/admin/federation/tenants/:id/peers` | 🔒 admin | Tenant peers |
| `POST` | `/admin/federation/tenants/:id/peers` | 🔒 admin | Add peer |
| `POST` | `/admin/federation/peers/:peerId/test` | 🔒 admin | Test peer connectivity |
| `GET` | `/admin/migrations/status` | 🔒 admin | Migration status |
| `POST` | `/admin/migrations/run` | 🔒 admin | Run migrations |
| `POST` | `/admin/migrations/rollback` | 🔒 admin | Rollback migration |
| `GET` | `/admin/scoring/summary` | 🔒 admin | Risk scoring summary |
| `GET` | `/admin/scoring/ioc/:id` | 🔒 admin | IOC score breakdown |
| `POST` | `/admin/scoring/rescore` | 🔒 admin | Trigger rescoring |

---

## Admin — Config

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/admin/config/feeds` | 🔒 admin | List feeds |
| `POST` | `/admin/config/feeds` | 🔒 admin | Create feed |
| `PUT` | `/admin/config/feeds/:id` | 🔒 admin | Update feed |
| `DELETE` | `/admin/config/feeds/:id` | 🔒 admin | Delete feed |
| `GET` | `/admin/config/api-keys` | 🔒 admin | List API keys |
| `POST` | `/admin/config/api-keys` | 🔒 admin | Create API key |
| `PUT` | `/admin/config/api-keys/:id` | 🔒 admin | Update API key |
| `DELETE` | `/admin/config/api-keys/:id` | 🔒 admin | Delete API key |
| `POST` | `/admin/config/api-keys/:id/test` | 🔒 admin | Test API key |
| `GET` | `/admin/config/services` | 🔒 admin | List services |
| `POST` | `/admin/config/services` | 🔒 admin | Create service |
| `PUT` | `/admin/config/services/:id` | 🔒 admin | Update service |
| `DELETE` | `/admin/config/services/:id` | 🔒 admin | Delete service |
| `GET` | `/admin/config/settings` | 🔒 admin | System settings |
| `PUT` | `/admin/config/settings/:key` | 🔒 admin | Update setting |
| `DELETE` | `/admin/config/settings/:key` | 🔒 admin | Delete setting |

---

## Admin — Sandbox

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/admin/sandbox/test-feed` | 🔒 admin | Test feed URL |
| `POST` | `/admin/sandbox/test-endpoint` | 🔒 admin | Test arbitrary endpoint |

---

## Operations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ops/workers` | ✓ | Worker status |
| `GET` | `/ops/system` | ✓ | System overview (all services) |
| `GET` | `/ops/ingestion` | ✓ | Ingestion pipeline stats |
| `GET` | `/ops/enrichment` | ✓ | Enrichment pipeline stats |
| `GET` | `/ops/embedding` | ✓ | Vector embedding stats |
| `GET` | `/ops/metrics/prometheus` | — | Prometheus metrics export |

---

## Monitoring

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/monitoring/health` | ✓ | System health |
| `GET` | `/monitoring/feeds` | ✓ | Feed status |
| `GET` | `/monitoring/feeds/:feedId` | ✓ | Feed detail |
| `GET` | `/monitoring/metrics/growth` | ✓ | Growth metrics |
| `GET` | `/monitoring/metrics/performance` | ✓ | Performance metrics |
| `GET` | `/monitoring/metrics/errors` | ✓ | Error metrics |

---

## OpenGate (Developer Portal)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/opengate` | — | Portal info |
| `POST` | `/opengate/keys` | ✓ | Create user API key |
| `GET` | `/opengate/keys` | ✓ | List user API keys |
| `DELETE` | `/opengate/keys/:id` | ✓ | Revoke API key |
| `GET` | `/opengate/profile` | ✓ | User profile |
| `GET` | `/opengate/usage` | ✓ | API usage stats |
| `GET` | `/opengate/admin/users` | 🔒 admin | Admin user list |

---

## Users (Legacy)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/users` | 🔒 admin | List users |
| `GET` | `/users/:id` | 🔒 admin | Get user |
| `POST` | `/users` | 🔒 admin | Create user |
| `PUT` | `/users/:id` | 🔒 admin | Update user |
| `DELETE` | `/users/:id` | 🔒 admin | Delete user |
| `POST` | `/users/:id/activate` | 🔒 admin | Activate |
| `POST` | `/users/:id/deactivate` | 🔒 admin | Deactivate |
| `GET` | `/users/roles/list` | ✓ | List roles |

---

## Audit (Legacy)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/audit` | 🔒 admin, analyst | Audit log |
| `GET` | `/audit/stats` | 🔒 admin | Audit stats |
| `GET` | `/audit/entity/:type/:id` | 🔒 admin, analyst | Entity audit trail |

---

## Web Search

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/web-search` | ✓ | Submit web search job |
| `GET` | `/web-search/:jobId` | ✓ | Get search results |

---

## Streaming

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/streaming/subscribe` | ✓ | Subscribe to event stream |
| `GET` | `/admin/events` | ✓ | List events |
| `GET` | `/admin/pipeline-events` | ✓ | Pipeline events stream |

---

## Bulk Operations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/bulk/export` | ✓ | Bulk export |
| `POST` | `/bulk/import` | ✓ | Bulk import |
| `POST` | `/bulk/lookup` | ✓ | Bulk lookup |

---

## Advanced Search

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/search/iocs` | ✓ | Advanced IOC search |
| `POST` | `/search/vulnerabilities` | ✓ | Advanced CVE search |
