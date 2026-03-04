# V3 Threat Intelligence Platform - Deployment Guide

## Prerequisites

- **Node.js** 20+ or **Bun** 1.0+
- **PostgreSQL** 16+
- **Redis** 7+
- **OpenSearch** 2.x (optional, for vector search)
- **Docker** \u0026 **Docker Compose** (for containerized deployment)

---

## Quick Start (Development)

### 1. Clone and Install

```bash
cd v3-backend-api-rinjani
pnpm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your database credentials and API keys
```

### 3. Start Docker Services

```bash
docker compose up -d
```

This starts:
- PostgreSQL (port 5432)
- Redis (port 6379)
- OpenSearch (port 9200)
- OpenSearch Dashboards (port 5601)

### 4. Run Database Migrations

```bash
# Push schema to database
pnpm --filter @rinjani/db push
```

### 5. Start Development Servers

```bash
# Start all services (API + Worker)
pnpm dev
```

**Services:**
- API: http://localhost:3001
- GraphQL Playground: http://localhost:3001/graphql
- Dashboard: http://localhost:3001 (static files in apps/dashboard)

---

## Production Deployment

### Option 1: Docker Compose

```bash
# Build production images
docker compose -f docker-compose.prod.yml build

# Start services
docker compose -f docker-compose.prod.yml up -d
```

### Option 2: Kubernetes (Helm)

```bash
# Add Helm dependencies
helm dependency update ./helm/v3-threat-intel

# Install chart
helm install v3-ti ./helm/v3-threat-intel \
  --set api.image.tag=latest \
  --set worker.image.tag=latest \
  --set postgresql.auth.password=YOUR_PASSWORD \
  --set redis.auth.password=YOUR_PASSWORD
```

**Helm Values:**
- `api.replicas` - Number of API pods (default: 2)
- `worker.replicas` - Number of worker pods (default: 1)
- `ingress.enabled` - Enable ingress (default: true)
- `ingress.tls.enabled` - Enable TLS (default: true)

### Option 3: Manual Deployment

```bash
# Build applications
pnpm build

# Start API server
cd apps/api
NODE_ENV=production node dist/index.js

# Start worker (separate process)
cd apps/worker
NODE_ENV=production node dist/index.js
```

---

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/db` |
| `JWT_SECRET` | Secret for JWT tokens | Generate with `openssl rand -hex 32` |
| `PORT` | API server port | `3001` |

### Optional (Intel Feeds)

| Variable | Description |
|----------|-------------|
| `ALIENVAULT_API_KEY` | AlienVault OTX API key |
| `CVE_API_KEY` | NIST NVD API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `RISKIQ_API_KEY` | RiskIQ PassiveTotal key |

See `.env.example` for full list.

---

## Database Migrations

### Push Schema (Development)

```bash
pnpm --filter @rinjani/db push
```

### Generate Migration (Production)

```bash
pnpm --filter @rinjani/db generate
pnpm --filter @rinjani/db migrate
```

---

## Feed Sync

### Manual Sync

```bash
# Sync all feeds once
pnpm --filter @rinjani/worker sync:feeds

# Sync specific feed
pnpm --filter @rinjani/worker sync:cisa
pnpm --filter @rinjani/worker sync:alienvault
```

### Daemon Mode

```bash
# Continuous sync (runs every hour)
pnpm --filter @rinjani/worker dev
```

### Kubernetes CronJobs

Helm chart includes CronJobs for:
- CISA KEV: Every 6 hours
- AlienVault OTX: Every 4 hours
- MITRE ATT&CK: Daily

---

## Monitoring

### Health Checks

```bash
curl http://localhost:3001/health
```

### Metrics (OpenTelemetry)

Set `OTEL_ENABLED=true` and configure `OTEL_ENDPOINT`:

```bash
OTEL_ENABLED=true
OTEL_ENDPOINT=http://localhost:4318
```

### Logs

```bash
# Docker logs
docker logs v3-api
docker logs v3-worker

# Kubernetes logs
kubectl logs -f deployment/v3-ti-api
kubectl logs -f deployment/v3-ti-worker
```

---

## Security

### API Authentication

**JWT Tokens:**
```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "your-api-key"}'
```

**API Keys:**
```bash
curl http://localhost:3001/v1/vulnerabilities \
  -H "X-API-Key: your-api-key"
```

### TLS/HTTPS

For production, enable TLS in Kubernetes ingress or use a reverse proxy (nginx, Traefik).

---

## Troubleshooting

### Database Connection Errors

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
psql postgresql://postgres:postgres@localhost:5432/rinjani_v3
```

### Worker Not Syncing

```bash
# Check worker logs
docker logs v3-worker

# Verify DATABASE_URL is set
echo $DATABASE_URL
```

### Port Already in Use

```bash
# Kill process on port 3001
lsof -ti:3001 | xargs kill -9
```

---

## Backup \u0026 Restore

### Database Backup

```bash
pg_dump -U postgres rinjani_v3 \u003e backup.sql
```

### Database Restore

```bash
psql -U postgres rinjani_v3 \u003c backup.sql
```

---

## Scaling

### Horizontal Scaling (Kubernetes)

```bash
# Scale API pods
kubectl scale deployment v3-ti-api --replicas=5

# Scale worker pods
kubectl scale deployment v3-ti-worker --replicas=3
```

### Vertical Scaling

Update resource limits in `helm/v3-threat-intel/values.yaml`:

```yaml
api:
  resources:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "2Gi"
      cpu: "2000m"
```

---

## Support

- **Documentation**: See README.md
- **Issues**: GitHub Issues
- **Architecture**: See README.md
