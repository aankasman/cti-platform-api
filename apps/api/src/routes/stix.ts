/**
 * STIX 2.1 API Routes
 * 
 * Provides STIX bundle export endpoints for interoperability.
 */

import { Hono } from 'hono';
import { generateSTIXBundle, getIOCAsSTIX, getThreatActorAsSTIX, getVulnerabilityAsSTIX } from '@rinjani/core/stix';
import { NotFoundError } from '../lib/errors';
import { StixBundleQuerySchema } from '../lib/schemas';

export const stixRouter = new Hono();

// ============================================================================
// Bundle Export
// ============================================================================

/**
 * GET /v2/stix/bundle
 * 
 * Export a STIX 2.1 bundle containing IOCs, Threat Actors, and Vulnerabilities.
 * 
 * Query Parameters:
 * - include: comma-separated list of object types (iocs,threats,vulnerabilities)
 * - limit: max objects per type (default: 1000)
 * - type: filter IOCs by type (ip, domain, hash-sha256, etc.)
 * - source: filter IOCs by source (alienvault, abusessl, etc.)
 * - severity: filter by severity (low, medium, high, critical)
 */
stixRouter.get('/bundle', async (c) => {
    const { include: includeRaw, limit, type, source, severity } = StixBundleQuerySchema.parse(c.req.query());
    const include = includeRaw?.split(',') || ['iocs', 'threats', 'vulnerabilities'];

    const bundle = await generateSTIXBundle({
        includeIOCs: include.includes('iocs'),
        includeThreatActors: include.includes('threats'),
        includeVulnerabilities: include.includes('vulnerabilities'),
        iocLimit: limit,
        threatActorLimit: Math.min(limit, 100),
        vulnerabilityLimit: limit,
        iocType: type,
        iocSource: source,
        severity,
    });

    // Set appropriate headers for STIX content
    c.header('Content-Type', 'application/stix+json;version=2.1');
    c.header('X-STIX-Objects-Count', String(bundle.objects.length));

    return c.json(bundle);
});

// ============================================================================
// Single Object Export
// ============================================================================

/**
 * GET /v2/stix/indicator/:id
 * Export a single IOC as a STIX Indicator
 */
stixRouter.get('/indicator/:id', async (c) => {
    const { id } = c.req.param();

    const indicator = await getIOCAsSTIX(id);

    if (!indicator) {
        throw new NotFoundError('IOC', id);
    }

    c.header('Content-Type', 'application/stix+json;version=2.1');
    return c.json(indicator);
});

/**
 * GET /v2/stix/threat-actor/:id
 * Export a single Threat Actor as STIX
 */
stixRouter.get('/threat-actor/:id', async (c) => {
    const { id } = c.req.param();

    const actor = await getThreatActorAsSTIX(id);

    if (!actor) {
        throw new NotFoundError('Threat actor', id);
    }

    c.header('Content-Type', 'application/stix+json;version=2.1');
    return c.json(actor);
});

/**
 * GET /v2/stix/vulnerability/:id
 * Export a single Vulnerability as STIX
 */
stixRouter.get('/vulnerability/:id', async (c) => {
    const { id } = c.req.param();

    const vuln = await getVulnerabilityAsSTIX(id);

    if (!vuln) {
        throw new NotFoundError('Vulnerability', id);
    }

    c.header('Content-Type', 'application/stix+json;version=2.1');
    return c.json(vuln);
});

// ============================================================================
// STIX Info
// ============================================================================

stixRouter.get('/', (c) => {
    return c.json({
        name: 'RinjaniAnalytics STIX 2.1 API',
        version: '2.1',
        specification: 'https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html',
        endpoints: {
            bundle: 'GET /v2/stix/bundle - Export full STIX bundle',
            indicator: 'GET /v2/stix/indicator/:id - Export single indicator',
            threatActor: 'GET /v2/stix/threat-actor/:id - Export threat actor',
            vulnerability: 'GET /v2/stix/vulnerability/:id - Export vulnerability',
        },
        supportedTypes: [
            'indicator',
            'threat-actor',
            'vulnerability',
            'identity',
        ],
    });
});

export default stixRouter;
