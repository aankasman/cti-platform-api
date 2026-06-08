# Roadmap

> Status: **aspirational, not contractual.** This is a single-maintainer
> project (with Claude Code as a pair-programming partner). Dates are
> targets, not commitments. Phases get re-ordered when real-world usage
> tells us what matters and what doesn't.

Last reviewed: **2026-06-05**.

## Status legend

| Marker | Meaning |
|---|---|
| 🟢 Shipped | In `master`, documented, used in production |
| 🟡 In flight | Branch open or active design |
| ⚪ Planned | Scoped, not started |
| 🔵 Considering | On the table, awaiting signal from users |

## Guiding principles

1. **Signal-per-engineering-hour first.** A single enricher that filters
   30% of IOCs as benign scanner noise beats a beautiful workflow editor.
2. **Read the data, then write the feature.** Every phase below leans on
   schemas we already have or trivially extend — not a from-scratch model.
3. **Integrate, don't compete.** A built-in SIEM is a tar pit. A clean
   SIEM exporter ships in a week. Pick the latter.
4. **LLMs as analyst surfaces, not as a chatbot widget.** Specific,
   evaluated prompts wired into specific UI panels — never a generic
   "chat with your data" sidebar.
5. **Solo-developer scope.** If a phase needs a team, it gets cut or
   sliced thinner until one person can ship it and maintain it.

---

## Phase 1 · Enrichment & Detection-as-Code

**Target window: 2026-06 → 2026-07**  ·  **Status: 🟡 In flight** (10 of 11 items shipped — VirusTotal v3 + AbuseIPDB already in master since pre-Phase-1; EPSS, Shodan, inKev shipped 2026-06-05; urlscan.io + GreyNoise shipped 2026-06-08; Sigma ingester + MITRE tag mapping + YARA persistence + scan-sample upload shipped 2026-06-08)

The highest-leverage phase: every enricher we add makes existing
dashboard cards more decision-useful, with near-zero schema churn.

### IOC enrichment chain

Pluggable enricher pattern — runs on ingest *and* on-demand via API.

- 🟢 **urlscan.io — URL/domain reputation + screenshots**
  (shipped 2026-06-08: `enrichURLScan()` searches existing public scans
  via `/api/v1/search/?q=page.url:...` or `page.domain:...`, returns the
  latest verdict (malicious / categories / brands), page metadata, and
  screenshot URL. Free tier of 1000 searches/day with `URLSCAN_API_KEY`;
  works unauthenticated at lower volume. Added to the default source
  set for url + domain enrichment.)
- 🟢 **GreyNoise Community — internet-noise filter**
  (shipped 2026-06-08: `enrichGreyNoise()` hits the v3 Community endpoint,
  returns classification + noise/riot flags + scanner name. Drops benign
  scanners (Shodan, Censys, security researchers) from priority. Community
  endpoint works without `GREYNOISE_API_KEY` at 50 lookups/day; with a
  free key, 10k/day. Added to the default source set for ip enrichment.)
- 🟢 **AbuseIPDB — community-reported abusive IPs**
  (already in master pre-Phase-1: `enrichAbuseIPDB()` in
  `packages/core/src/enrichment.ts` hits `/api/v2/check` with a 90-day
  abuse-confidence lookup; falls back gracefully when no
  `ABUSEIPDB_API_KEY` is set. Registered in the enrichment dispatch
  map and the provider registry.)
- 🟢 **Shodan InternetDB — passive enrichment, no key required**
  (shipped 2026-06-05: `enrichShodan()` falls back to internetdb.shodan.io
  when no `SHODAN_API_KEY` is set; surfaces open ports, hostnames, and
  known CVEs per IP. Default enrichment sources now include `shodan`
  alongside `virustotal` + `geoip`.)
- 🟢 **VirusTotal v3 — multi-engine consensus**
  (already in master pre-Phase-1: `enrichVirusTotal()` uses the v3 API
  for IPs / domains / URLs / hashes, returns harmless/suspicious/malicious
  vendor counts and the top-rated tags. Default enrichment source
  alongside Shodan + GeoIP.)
- ⚪ PhishTank + OpenPhish — confirmed-phishing cross-check

### Vulnerability scoring upgrades

- 🟢 **EPSS (FIRST.org) — exploit-prediction score**
  (shipped 2026-06-05: daily worker downloads `epss-scores-current.csv.gz`,
  bulk-UPDATEs `vulnerabilities.epss_score` + `epss_percentile`. First
  backfill scored 6,503 of 7,095 vulns; 951 sit at EPSS ≥ 0.5. Surfaced
  on the vulns list table, CVE drawer, and CVE detail page. Transforms
  *"X critical CVEs"* into *"X critical with EPSS ≥ 0.7"*.)
- ⚪ CVSS v4 fields alongside existing v3
- 🟢 **Surface `inKev` boolean on every vuln panel**
  (shipped 2026-06-05: data was already in `vulnerabilities.is_exploited`;
  `/v1/landscape/overview` now returns `vulnerabilities.inKev` count, the
  Threat Command tile renders "N high · M crit · K KEV", and the vulns
  list already had a KEV flame column + KEV-only filter toggle.)

### Detection rules — Sigma & YARA

- 🟢 **Sigma rule ingester + library API**
  (shipped 2026-06-08: `packages/core/src/sigma.ts` parses upstream
  SigmaHQ YAML into our `detection_rules` table with `rule_type='sigma'`,
  preserving the full `detection:` block + `logsource` so downstream
  converters (Splunk, Elastic, OpenSearch) have something to transform.
  Single rules or `---`-separated bundles. `POST /v1/sigma/rules` takes
  raw YAML or JSON-wrapped; `POST /v1/sigma/import/url` pulls from a
  URL. Pre-existing MISP-Galaxy sigma ingest keeps populating
  metadata-only rows alongside.)
- 🟢 **Sigma `tags:` → MITRE ATT&CK technique mapping**
  (shipped 2026-06-08: `attack.tNNNN[.NNN]` tags lift to canonical
  `TNNNN[.NNN]` IDs in `meta.mitre_techniques`; `attack.<kebab-tactic>`
  tags lift into `meta.mitre_tactics`. Queryable via
  `GET /v1/sigma/by-technique/:techniqueId` using a JSONB containment
  predicate. Lower-case Sigma convention round-trips to upper-case
  MITRE form.)
- 🟢 **YARA rule storage + scan-uploaded-sample endpoint**
  (shipped 2026-06-08: in-memory YARA engine now persists user-added
  rules to `detection_rules` with `rule_type='yara'` and re-hydrates on
  startup so custom rules survive restart. Built-in rules stay
  code-only. `POST /v1/yara/scan-sample` accepts multipart/form-data
  or `application/octet-stream` up to 25 MiB; binary samples scan via
  latin1 decoding so hex patterns match raw bytes.)

---

## Phase 2 · STIX 2.1 first-class & Federation

**Target window: 2026-08 → 2026-09**  ·  **Status: 🟢 Closed** (5 of 5 items shipped — provenance/TLP + bundle import expansion + outbound TAXII push 2026-06-08 AM; STIX entity tables for campaign/course-of-action/infrastructure + relationship_type CHECK constraint + Neo4j auto-hydrate on relationship INSERT 2026-06-08 PM. `bundle.tar` packaging and hop-based TLP propagation deferred as small follow-ons; not blockers for federation.)

We speak TAXII but the internal model is still IOC-centric. STIX as
source of truth opens up federation between Rinjani instances and with
MISP / OpenCTI / vendor stacks.

- 🟢 **Full STIX 2.1 entity coverage** for the 10 Phase-2 SDO types:
  (shipped 2026-06-08: new `campaigns`, `courses_of_action`,
  `infrastructure` tables in migration 0046. The remaining seven were
  already covered before this phase started — `indicator` ↔ `iocs`,
  `vulnerability` ↔ `vulnerabilities`, `threat-actor` ↔ `threat_actors`,
  `malware` ↔ `malware`, `tool` ↔ `tools` (MITRE schema),
  `attack-pattern` ↔ `techniques` (the MITRE seed), `intrusion-set` is
  aliased to `threat_actors` because the relational model doesn't
  distinguish them. `note` and `opinion` remain skip-only by design —
  they're commentary, not entities, and the importer's
  `skippedTypes` counter surfaces them to the dashboard.)
- 🟢 **Typed relationships + Neo4j auto-hydration**
  (shipped 2026-06-08: `relationship_type` now constrained to the STIX 2.1
  §5.7 SRO common vocab + project-specific extensions via DB CHECK
  constraint (migration 0045) and a Zod enum on `POST /v1/relationships`.
  Both the user-facing route AND the STIX-bundle importer fire
  `autoHydrateRelationship()` on INSERT — a side-effect that MERGEs the
  matching Cypher edge in Neo4j. Mismatched labels, missing nodes, or
  driver failures are logged but never block the SQL write. Existing
  shortest-path endpoint at `findShortestPath(from, to, maxDepth)` now
  sees a fully-hydrated graph.)
- 🟡 **Bundle import/export** — JSON works both ways with full SDO
  coverage; `.tar` packaging follow-on. (shipped 2026-06-08: import
  expanded to handle `malware`, `campaign`, `course-of-action`,
  `infrastructure`, and `relationship` with full ref-resolution.
  `identity` + `marking-definition` counted but not persisted (they're
  bundle metadata); `note` + `opinion` skip-only.)
- 🟢 **TAXII 2.1 push client**
  (shipped 2026-06-08: new `taxii_remote_targets` table + REST CRUD at
  `/v1/taxii/remote-targets/*`, plus `POST /v1/taxii/remote-targets/:id/push`
  for one-shot pushes and `POST /v1/taxii/push-all` for the fan-out. Per-target
  filter mirrors `STIXExportOptions`, so each remote can subscribe to a
  different slice — e.g. "TLP:GREEN urlhaus + threatfox IOCs only, no
  threat-actors". Bearer token resolves from `config_api_keys.id` or
  the `TAXII_PUSH_API_KEY` env var. Last-push status persists on the
  target row.)
- 🟢 **Confidence + TLP marking propagation**
  (shipped 2026-06-08: `stixProvenance.ts` moved to `@rinjani/core/stixProvenance`
  and wired into the export pipeline. Every emitted `indicator`, `threat-actor`,
  and `vulnerability` now carries `created_by_ref`, `object_marking_refs`,
  `confidence` (0-100), and the custom `extension-definition--provenance`
  block with merge history + data-quality scoring. Per-source TLP defaults
  map known feeds to sensible markings (alienvault → WHITE,
  virustotal → GREEN, misp → AMBER); operator can override per-bundle
  via `STIXExportOptions.defaultTlp`. The bundle now also emits the
  referenced identity + marking-definition SDOs as required by STIX 2.1.
  Hop-based TLP propagation through the `relationships` graph is the
  follow-up that closes this fully.)

> **Differentiator we're leaning into**: graph-native attribution.
> *"Everything attributed to this intrusion set through any path
> ≤ 3 hops"* is a Cypher query for us; vendor stacks fake it with
> recursive SQL self-joins.

---

## Phase 3 · LLM analyst features

**Target window: 2026-10 → 2026-11**  ·  **Status: 🟡 In flight** (2 of 5 items shipped — embedding similarity backend (pre-Phase-3) + actor activity summarisation shipped 2026-06-08)

Provider abstraction (Gemini / OpenRouter / Ollama) already exists. This
phase wires it into the analyst workflow, deliberately scoped to specific
surfaces rather than a generic chat widget.

- ⚪ **Report ingestion** — paste a PDF or URL; extract IOCs + TTPs +
  actors into STIX entities for review
- 🟢 **Actor activity auto-summarisation**
  (shipped 2026-06-08: `GET|POST /v1/threat-actors/:id/summary?days=30`
  reads the actor row + recent relationships, outgoing-edge distribution,
  top malware/tools, recent campaigns, and recent IOCs in a configurable
  lookback window. The activity block feeds a strict RAG prompt that
  explicitly forbids hallucinating IOCs / campaign names / malware that
  aren't in the data. Returns markdown plus a structured `activity` block
  so the UI can show "based on N IOCs + M campaigns". Provider
  override (`gemini` | `openrouter` | `ollama`) supported per call.)
- 🟢 **Embedding similarity** — *"have we seen this before"* loop
  (backend already in master pre-Phase-3: `POST /v1/search/vector` runs
  k-NN against OpenSearch's `knn_vector` index, `GET /v1/search/similar/:docId`
  returns the N most semantically-similar docs for any IOC / pulse / CVE.
  Embeddings come from `@xenova/transformers` locally (384-dim, no
  network) or any of the configured cloud providers. Batch reindex via
  `POST /v2/search/rebuild-with-vectors`. The dashboard-side "Similar
  IOCs" sidebar is the remaining work and lives in the dashboard repo.)
- ⚪ **Natural-language → Cypher** — query Neo4j without learning
  Cypher; small model, prompt-tuned to the schema
- ⚪ **Hypothesis tracking** — *"I think Group A is using infrastructure
  X"* → LLM grades evidence as it accumulates from feeds

> **Honest trade-off**: highest marketing value per hour invested IF
> prompts stay tight and evaluated. Will become a tar pit if we let it
> sprawl. Each surface ships with golden-output evals before merge.

---

## Phase 4 · Outbound integrations

**Target window: 2026-12 → 2027-02**  ·  **Status: ⚪ Planned**

Make the platform an active participant in the analyst's stack, not a
walled garden.

- ⚪ **Notification routing** — Slack, Teams, Discord, Email, PagerDuty,
  generic webhook. Rule-based: `severity=critical AND inKev=true →
  PagerDuty`
- ⚪ **SIEM exporters** — Splunk HEC, Elastic, Microsoft Sentinel;
  formats: CEF, LEEF, ECS, STIX bundle
- ⚪ **SOAR-style playbooks** — our Workbench / FlowProducer pattern is
  already a playbook engine; expose it as a `Trigger → Steps` DSL
- ⚪ **Blocklist exports** — CSV, MISP feed, Fortinet, Palo Alto, Cisco
  firewall formats; cached, signed, served at stable subscribable URLs
- ⚪ **Sandbox triggers** — Joe Sandbox, ANY.RUN, Hybrid Analysis (kick
  off, store the report, link it to the originating IOC)
- ⚪ **Ticketing** — JIRA + GitHub Issues two-way sync for investigation
  tracking

---

## Phase 5 · Surface monitoring

**Target window: 2027-03 → 2027-05**  ·  **Status: 🔵 Considering**

Where we stop being a feed aggregator and start being a sensor network.
Ethics and scope matter here — each item is framed deliberately narrow.

- 🔵 **Brand / typo-squat monitoring** — CertStream + Levenshtein /
  DNS-twist; alerts on newly registered look-alikes of monitored domains
- 🔵 **Leaked credentials** — HIBP API integration scoped to monitored
  domains
- 🔵 **Paste-site monitoring** — public Telegram channels, GitHub Gist
  firehose, pastebin replacements (no scraping behind auth)
- 🔵 **Dark web** — Ahmia indexed search only. No direct `.onion`
  crawling on a single-VPS deployment — operationally messy, legally
  fraught in several jurisdictions, and outside solo-maintainer scope
- 🔵 **Threat-actor TTP changelog** — diff MITRE updates per group,
  alert when a tracked actor adopts a new technique

---

## Phase 6 · Platform & multi-tenancy

**Target window: 2027-06+**  ·  **Status: 🔵 Considering**

Deferred deliberately. We add this when a second tenant asks — not
before — otherwise it's over-engineering for a phantom requirement.

- 🔵 Hard tenant isolation: Postgres RLS + per-tenant OpenSearch
  index pattern + Neo4j label namespacing
- 🔵 Granular RBAC: per-source, per-TLP, per-actor visibility
- 🔵 SCIM provisioning + Keycloak federation (Keycloak hook already exists)
- 🔵 Audit-log streaming to S3 / ClickHouse
- 🔵 API-key scoping (admin / analyst / etc. exist — needs per-resource scope)
- 🔵 Per-tenant data-residency hooks (gateway routes by tenant claim)

---

## Cross-cutting (always-on, no phase)

Quality-of-life items that pay back every phase above. Worked on in the
margins, not gated behind a milestone.

- ⚪ **OpenTelemetry** through the BullMQ pipeline → expose trace IDs in
  the embedded Workbench. Workbench already shows the pipeline; this
  shows it *with timings and per-step errors*
- ⚪ **OpenSearch ILM** — hot/warm/cold policies; indices currently
  grow unbounded
- ⚪ **IOC decay** — `decayed_at` based on
  `(source_confidence × age_factor)` so old OTX pulses don't keep
  pinging the dashboard forever
- ⚪ **TAXII contract tests** — cross-test against real PyTAXII2 and
  libtaxii clients; our endpoint should pass MISP & OpenCTI clients'
  real requests
- ⚪ **Performance budget** — `/v1/stats/overview` stays under 200 ms
  p95 as data grows; CI canary
- ⚪ **Feed-parser fuzzing** — every parser is an attack surface; AFL++
  on OTX, MISP, STIX parsers in CI

---

## What we won't build

Deliberate non-goals. Saying "no" early is how a solo project stays
shippable.

| Item | Why not |
|---|---|
| Built-in SIEM | Excellent ones exist; we integrate, not compete |
| Generic OSINT web crawler | A year of work to compete with `theHarvester`, `Maltego`, etc. — we narrow to cert streams + paste sites instead |
| Visual workflow editor on top of Workbench | Workbench's existing UI is good enough; the DSL approach in Phase 4 is leaner |
| Native mobile app | Dashboard is responsive; a separate React Native app is a tar pit for a solo dev |
| Built-in case management | JIRA / GitHub two-way sync covers 95% of this for 5% of the effort |
| Authoritative malware analysis | Sandbox *triggers* yes (Phase 4); building a sandbox no |

---

## Differentiators we're doubling down on

What we have that vendor stacks and most indie alternatives don't:

1. **Graph-native attribution** (Neo4j as a first-class store, not a
   bolt-on). Most indie CTI tools fake graph queries with SQL
   self-joins; we model the graph as the graph
2. **Embedded pipeline visibility** — Workbench fork at `/admin/workbench`
   lets analysts debug ingestion themselves, in the same tab they log
   in to. Rare even in vendor products
3. **LLM as analyst, not as chatbot** — narrow surfaces (summarisation,
   IOC extraction, similarity) with golden-output evals, not a generic
   "chat with your data" widget
4. **Vector search ready** — OpenSearch already configured with vector
   support; Phase 3 ships the wiring, but we're 80% there infrastructurally

---

## Contributing to the roadmap

This file is the source of truth, but the conversation happens elsewhere:

- **Feature ideas** → [GitHub Discussions](https://github.com/rinjanianalytics/cti-platform-api/discussions/categories/ideas)
- **Bugs & well-scoped work** → [GitHub Issues](https://github.com/rinjanianalytics/cti-platform-api/issues)
- **PRs against the roadmap** → especially welcome for Phase 1 enrichers;
  the pattern is well-defined, the scope is bounded, and one enricher
  per PR keeps the review surface tight

If you're working on something here, **drop a comment in the
corresponding issue** so we don't duplicate effort.

---

## Related repos

- [cti-platform-dashboard](https://github.com/rinjanianalytics/cti-platform-dashboard) — Next.js operator UI; its roadmap items (tri-state health, sparklines, etc.) live in that repo's issues
