# Security Policy

## Supported Versions

The project currently maintains a single rolling line on `master`. Security
patches land there and are tagged at `v3.x.x` releases.

| Branch / tag | Status |
|---|---|
| `master` (latest) | ✅ supported |
| Tagged `v3.x.x` releases (latest minor) | ✅ supported |
| Older `v3.x.x` releases | ⚠️ best-effort — please upgrade |

## Reporting a vulnerability

**Do not file a public GitHub issue** for security reports. The dashboard and
backend handle threat-intel data and authenticate against multiple
datastores; a public issue is the wrong place to surface an exploit.

Email **[rinjanianalytics@gmail.com](mailto:rinjanianalytics@gmail.com)** with:

- A description of the issue
- Steps to reproduce (or proof-of-concept if appropriate)
- Affected version / commit SHA
- Your name + how you'd like to be credited (or "anonymous")

We aim to:

- Acknowledge within **2 business days**
- Provide an initial assessment within **5 business days**
- Ship a fix and coordinated disclosure within **30 days** for critical
  issues, longer for issues requiring a major refactor

We do not currently run a paid bounty programme, but we credit reporters by
name (or handle) in the changelog and release notes, with permission.

## In scope

- Authentication & authorisation logic ([apps/api/src/middleware/auth.ts](apps/api/src/middleware/auth.ts), [apps/api/src/services/oauth.ts](apps/api/src/services/oauth.ts))
- Input validation on all REST / GraphQL / TAXII / WebSocket entry points
- SQL / NoSQL / Cypher / OpenSearch injection vectors
- Secrets handling and the bootlock model ([apps/api/src/lib/bootlock.ts](apps/api/src/lib/bootlock.ts))
- Cookie + JWT handling, including the cookie-auth fallback used by the
  embedded Workbench dashboard
- The vendored `packages/workbench-core/` fork — we own its supply-chain
  exposure, see [packages/workbench-core/VENDOR.md](packages/workbench-core/VENDOR.md)
- The dashboard repo's auth + cookie mirroring code

## Out of scope

- Vulnerabilities in third-party dependencies that we've already pinned to
  patched versions (check [SECURITY_AUDIT.md](SECURITY_AUDIT.md) and
  `pnpm.overrides` in `package.json` before reporting)
- Self-XSS, social-engineering, physical access
- DoS via volumetric request flooding (handled at infra layer, not app)
- Findings against `.env.example` (it ships placeholder values by design)

## Recent audits

- **2026-05-27** — Full dependency + middleware audit triggered by the
  TanStack supply-chain compromise (CVE-2026-45321). See
  [SECURITY_AUDIT.md](SECURITY_AUDIT.md). Verified not compromised;
  hardened with version-floor `pnpm.overrides`.
