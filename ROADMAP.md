# Roadmap

> Status: **aspirational, not contractual.** This is a single-maintainer
> project (with Claude Code as a pair-programming partner). Dates are
> targets, not commitments. Phases get re-ordered when real-world usage
> tells us what matters and what doesn't.

Last reviewed: **2026-05-30**.

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

**Target window: 2026-06 → 2026-07**  ·  **Status: ⚪ Planned**

The highest-leverage phase: every enricher we add makes existing
dashboard cards more decision-useful, with near-zero schema churn.

### IOC enrichment chain

Pluggable enricher pattern — runs on ingest *and* on-demand via API.

- ⚪ urlscan.io (free, generous limit) — URL/domain reputation + screenshots
- ⚪ GreyNoise Community — internet-noise filter; expected to drop
  ~30% of ingested IOCs as benign mass scanners
- ⚪ AbuseIPDB — community-reported abusive IPs
- ⚪ Shodan InternetDB — passive enrichment, no key required
- ⚪ VirusTotal v3 — multi-engine consensus (free: 4 req/min)
- ⚪ PhishTank + OpenPhish — confirmed-phishing cross-check

### Vulnerability scoring upgrades

- ⚪ EPSS (FIRST.org) — exploit-prediction score; transforms
  *"X critical CVEs"* into *"X critical with EPSS ≥ 0.7"*
- ⚪ CVSS v4 fields alongside existing v3
- ⚪ Surface `inKev` boolean on every vuln panel (data already there)

### Detection rules — Sigma & YARA

- ⚪ Sigma rule library ingestion from SigmaHQ + custom rules
- ⚪ Map Sigma `tags:` → MITRE ATT&CK techniques (we already model these)
- ⚪ YARA rule storage + "scan uploaded sample" endpoint
  (rule store + match service only — no live execution)

---

## Phase 2 · STIX 2.1 first-class & Federation

**Target window: 2026-08 → 2026-09**  ·  **Status: ⚪ Planned**

We speak TAXII but the internal model is still IOC-centric. STIX as
source of truth opens up federation between Rinjani instances and with
MISP / OpenCTI / vendor stacks.

- ⚪ Full STIX 2.1 entity CRUD: `intrusion-set`, `campaign`, `malware`,
  `tool`, `course-of-action`, `attack-pattern`, `vulnerability`,
  `infrastructure`, `note`, `opinion`
- ⚪ Typed relationships (`uses`, `targets`, `attributed-to`,
  `mitigates`, `derived-from`) — Neo4j is already wired for this
- ⚪ Bundle import/export (JSON + `bundle.tar`)
- ⚪ **TAXII 2.1 push** (we currently only pull) — enables federation
  between two Rinjani instances, or pushing into MISP
- ⚪ Confidence + TLP marking propagation through relationships

> **Differentiator we're leaning into**: graph-native attribution.
> *"Everything attributed to this intrusion set through any path
> ≤ 3 hops"* is a Cypher query for us; vendor stacks fake it with
> recursive SQL self-joins.

---

## Phase 3 · LLM analyst features

**Target window: 2026-10 → 2026-11**  ·  **Status: ⚪ Planned**

Provider abstraction (Gemini / OpenRouter / Ollama) already exists. This
phase wires it into the analyst workflow, deliberately scoped to specific
surfaces rather than a generic chat widget.

- ⚪ **Report ingestion** — paste a PDF or URL; extract IOCs + TTPs +
  actors into STIX entities for review
- ⚪ **Auto-summarisation** — *"summarise the last 30 days of this
  actor's activity"* panel on actor pages
- ⚪ **Embedding similarity** — OpenSearch already has vector support;
  index every IOC + report and surface "similar to" sidebars. Closes the
  *"have we seen this before"* loop
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
