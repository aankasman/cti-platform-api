# Rinjani CTI Platform — Architecture

## System Overview

```mermaid
graph TB
    subgraph Dashboard["Dashboard (Next.js :3000)"]
        UI["42 Pages · React · SSR"]
        SSE_Client["SSE Client · Real-time Toasts"]
        APIClient["API Client · 200+ methods"]
    end

    subgraph Backend["Backend API (Hono :3001)"]
        Auth["Auth Middleware · API Key / Bearer"]
        RBAC["RBAC · 5 roles"]
        Routes["Route Groups · 87 files · 200+ endpoints"]
        Services["Service Layer"]
        Workers["BullMQ Workers"]
    end

    subgraph DataStores["Data Stores"]
        PG["PostgreSQL · Primary DB"]
        OS["OpenSearch · Full-text & Vector Search"]
        Neo4j["Neo4j · Graph Relations"]
        Redis["Redis · Cache & Queues"]
        Meili["MeiliSearch · Instant Search"]
    end

    subgraph External["External Services"]
        Feeds["Threat Intel Feeds"]
        SearXNG["SearXNG · Web Search"]
        Exa["Exa · Websets"]
        Enrich["VirusTotal · AbuseIPDB · Shodan"]
        N8N["n8n · Workflow Automation"]
        Vault["Vault · Secrets"]
        Keycloak["Keycloak · Identity"]
    end

    subgraph Monitoring["Monitoring"]
        Prometheus["Prometheus"]
        Grafana["Grafana Dashboards"]
    end

    UI --> APIClient
    SSE_Client -.->|EventSource| Routes
    APIClient -->|HTTP| Auth
    Auth --> RBAC --> Routes
    Routes --> Services
    Services --> PG
    Services --> OS
    Services --> Neo4j
    Services --> Redis
    Services --> Meili
    Workers -.->|BullMQ| Redis
    Workers --> PG
    Workers --> OS
    Workers --> Neo4j
    Services --> Feeds
    Services --> SearXNG
    Services --> Exa
    Services --> Enrich
    Services --> N8N
    Routes --> Vault
    Routes --> Keycloak
    Routes -.->|/ops/metrics/prometheus| Prometheus
    Prometheus --> Grafana
```

## Data Flow

```mermaid
flowchart LR
    subgraph Ingestion
        F["Threat Feeds"] --> Sync["Feed Sync Worker"]
        W["Web Search"] --> Scrape["SearXNG Scraper"]
        STIX_In["STIX Import"] --> Parse["STIX Parser"]
    end

    subgraph Processing
        Sync --> Q1["BullMQ Queue"]
        Scrape --> Q1
        Parse --> Q1
        Q1 --> Enrich["Enrichment Worker"]
        Enrich --> IOC_Extract["IOC Extractor"]
        IOC_Extract --> Embed["Vector Embedder"]
        Embed --> Score["Risk Scorer"]
    end

    subgraph Storage
        Score --> PG["PostgreSQL"]
        Score --> OS["OpenSearch"]
        Score --> Neo4j["Neo4j Graph"]
        Score --> Meili["MeiliSearch"]
    end

    subgraph Delivery
        PG --> API["REST API"]
        OS --> API
        Neo4j --> API
        API --> Dashboard["Dashboard"]
        API --> TAXII["TAXII Server"]
        API --> SSE["SSE Events"]
        SSE --> Dashboard
    end
```

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Runtime** | Node.js 20 + TypeScript 5 | Server runtime |
| **Web Framework** | Hono | HTTP routing, middleware |
| **Frontend** | Next.js 14 + React | Dashboard SSR/SSG |
| **Primary DB** | PostgreSQL (Drizzle ORM) | Structured data, relations |
| **Search** | OpenSearch | Full-text + 384-dim vector search |
| **Graph** | Neo4j | Entity relationships, attack paths |
| **Cache/Queues** | Redis + BullMQ | Caching, job queues, rate limiting |
| **Instant Search** | MeiliSearch | Typo-tolerant instant search |
| **Auth** | API Keys + Keycloak + Vault | Authentication & secrets |
| **Monitoring** | Prometheus + Grafana | Metrics & dashboards |
| **Automation** | n8n | Workflow orchestration |
| **ML/AI** | @xenova/transformers | Vector embeddings (384-dim) |

## Service Architecture

```mermaid
graph LR
    subgraph Core["Core Services"]
        IOC["IOC Service"]
        CVE["Vulnerability Service"]
        Actor["Threat Actor Service"]
        Sight["Sighting Service"]
    end

    subgraph Analysis["Analysis Services"]
        Search["Search Service"]
        Corr["Correlation Engine"]
        MITRE["MITRE ATT&CK"]
        Graph["Graph Analyzer"]
        Score["Risk Scorer"]
    end

    subgraph Enrichment["Enrichment"]
        VT["VirusTotal"]
        AIPDB["AbuseIPDB"]
        Shodan["Shodan"]
        OTX["AlienVault OTX"]
        TF["ThreatFox"]
    end

    subgraph Pipeline["Pipeline"]
        Ingest["Feed Ingestion"]
        Extract["IOC Extraction"]
        Embed["Vector Embedding"]
        Notify["Notification Engine"]
    end

    IOC --> Search
    IOC --> Corr
    CVE --> Search
    Actor --> MITRE
    Actor --> Graph
    Score --> IOC
    Score --> CVE

    Ingest --> Extract --> Embed --> Notify
    VT & AIPDB & Shodan --> Score
```

## Database Schema Overview

| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `iocs` | Indicators of Compromise | value, type, severity, risk_score, first/last_seen |
| `vulnerabilities` | CVE records | cve_id, cvss_score, severity, description |
| `threat_actors` | Named threat groups | name, aliases, motivation, sophistication |
| `sightings` | IOC observation records | ioc_id, source, confidence, observed_at |
| `web_intel_items` | Scraped web content | url, title, text_content, source |
| `web_intel_mentions` | IOC mentions in web content | item_id, ioc_value, ioc_type, context |
| `alert_rules` | User-defined alert rules | name, conditions, severity, enabled |
| `audit_log` | System activity audit | user_id, action, entity, timestamp |
| `playbooks` | SOAR playbook definitions | name, steps, trigger, last_run |
| `warninglists` | False-positive exclusion lists | name, type, entries |
| `yara_rules` | YARA detection rules | name, rule_content, enabled |
| `users` | Platform users | email, role, api_token, active |

## Deployment

```mermaid
graph TB
    subgraph Host["Host Machine"]
        Backend["Backend API :3001"]
        Dashboard["Dashboard :3000"]
        N8N_S["n8n :5678"]
    end

    subgraph Docker["Docker Services"]
        PG["PostgreSQL :5432"]
        OS["OpenSearch :9200"]
        Neo4j_S["Neo4j :7474/:7687"]
        Redis_S["Redis :6379"]
        Meili_S["MeiliSearch :7700"]
        Prometheus_S["Prometheus :9090"]
        Grafana_S["Grafana :3005"]
        SearXNG_S["SearXNG :8888"]
    end

    Backend --> PG & OS & Neo4j_S & Redis_S & Meili_S
    Dashboard --> Backend
    Prometheus_S --> Backend
    Grafana_S --> Prometheus_S
    Backend --> SearXNG_S
    Backend --> N8N_S
```

> See [DEPLOY.md](./DEPLOY.md) for full deployment instructions and [docs/API.md](./docs/API.md) for endpoint reference.
