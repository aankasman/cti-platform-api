/**
 * STIX 2.1 Bundle Import/Export Pipeline
 *
 * Full bidirectional STIX support:
 *   - Import:  Parse STIX 2.1 bundles → Extract SDOs → Persist IOCs/CVEs/Actors
 *   - Export:  Query entities → Build STIX bundle with relationships
 *   - Validate: Structural validation without persisting
 *
 * Uses sql.raw() for dynamic queries and sql`` templates for static queries.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { db, sql, rawQuery } from '@rinjani/db';
import { createLogger } from '../../lib/logger';
import { requireAuth, requireRole } from '../../middleware/auth';
import { ValidationError } from '../../lib/errors';
import { StixImportSchema, StixExportSchema } from '../../lib/schemas';

const log = createLogger('STIX-Pipeline');

const stixPipeline = new Hono();

// ============================================================================
// Types
// ============================================================================

interface STIXBundle {
    type: 'bundle';
    id: string;
    objects: STIXObject[];
}

interface STIXObject {
    type: string;
    id: string;
    spec_version?: string;
    created?: string;
    modified?: string;
    name?: string;
    description?: string;
    pattern?: string;
    pattern_type?: string;
    valid_from?: string;
    valid_until?: string;
    labels?: string[];
    confidence?: number;
    external_references?: Array<{
        source_name: string;
        external_id?: string;
        url?: string;
    }>;
    relationship_type?: string;
    source_ref?: string;
    target_ref?: string;
    indicator_types?: string[];
    x_cvss_score?: number;
    aliases?: string[];
    roles?: string[];
    goals?: string[];
    sophistication?: string;
    resource_level?: string;
    primary_motivation?: string;
    identity_class?: string;
    definition_type?: string;
    definition?: Record<string, string>;
    [key: string]: unknown;
}

interface ImportResult {
    bundleId: string;
    totalObjects: number;
    imported: {
        indicators: number;
        vulnerabilities: number;
        threatActors: number;
        malware: number;
        relationships: number;
        identities: number;
        markings: number;
        skipped: number;
    };
    skippedTypes: Record<string, number>;
    errors: Array<{ objectId: string; error: string }>;
    dryRun: boolean;
}

// ============================================================================
// Pattern Parser
// ============================================================================

function patternToIOC(pattern: string): { type: string; value: string } | null {
    const match = pattern.match(/\[(\S+):value\s*=\s*'([^']+)'\]/);
    if (!match) return null;

    const stixType = match[1];
    const value = match[2];

    const typeMap: Record<string, string> = {
        'ipv4-addr': 'ip',
        'ipv6-addr': 'ip',
        'domain-name': 'domain',
        'url': 'url',
        'file': 'hash',
        'email-addr': 'email',
        'mac-addr': 'mac',
    };

    return { type: typeMap[stixType] || 'unknown', value };
}

function stixConfidenceToInternal(confidence?: number): number {
    return Math.min(100, Math.max(0, confidence || 50));
}

function stixLabelsToSeverity(labels?: string[]): string | null {
    if (!labels?.length) return null;
    const severityMap: Record<string, string> = {
        'anomalous-activity': 'low',
        'benign': 'info',
        'malicious-activity': 'high',
        'compromised': 'critical',
    };
    for (const label of labels) {
        if (severityMap[label]) return severityMap[label];
    }
    return null;
}

// ============================================================================
// Routes
// ============================================================================

/** POST /v1/stix/import — Import a STIX 2.1 bundle */
stixPipeline.post('/stix/import', requireAuth, requireRole('analyst'), async (c) => {
    const body = StixImportSchema.parse(await c.req.json().catch(() => ({})));

    const result = await importSTIXBundle(body as unknown as STIXBundle, body.dryRun);

    return c.json({ success: true, data: result }, result.errors.length > 0 ? 207 : 200);
});

/** POST /v1/stix/export — Export entities as a STIX 2.1 bundle */
stixPipeline.post('/stix/export', requireAuth, async (c) => {
    const { entityTypes, includeRelationships, limit } = StixExportSchema.parse(
        await c.req.json().catch(() => ({}))
    );

    const bundle = await exportSTIXBundle(entityTypes, includeRelationships, limit);

    return c.json(bundle, 200, {
        'Content-Disposition': `attachment; filename="stix_bundle_${Date.now()}.json"`,
        'Content-Type': 'application/json',
    });
});

/** POST /v1/stix/validate — Validate a STIX bundle without importing */
stixPipeline.post('/stix/validate', requireAuth, async (c) => {
    const body = await c.req.json();
    return c.json({ success: true, data: validateSTIXBundle(body) });
});

// ============================================================================
// Core Import
// ============================================================================

/**
 * Build a lookup from STIX object id ("indicator--abc", "malware--xyz") to
 * our internal {entityType, internalId} after first-pass inserts complete.
 * Used by the relationship pass to translate STIX source_ref / target_ref
 * into our (source_type, source_id, target_type, target_id) shape.
 */
type RefMap = Map<string, { entityType: string; internalId: string }>;

const STIX_TYPE_TO_INTERNAL: Record<string, string> = {
    'indicator': 'ioc',
    'vulnerability': 'vulnerability',
    'threat-actor': 'threat_actor',
    'malware': 'malware',
    'attack-pattern': 'technique',
    'campaign': 'campaign',
    'course-of-action': 'mitigation',
    'tool': 'tool',
    'identity': 'identity',
    'infrastructure': 'infrastructure',
};

function stripStixIdPrefix(stixId: string): string {
    const idx = stixId.indexOf('--');
    return idx >= 0 ? stixId.slice(idx + 2) : stixId;
}

/**
 * Fallback resolver: when a relationship references an SDO not present in
 * the same bundle (or one we don't persist as a top-level entity, like a
 * technique referenced by MITRE id), derive the (entityType, id) from the
 * STIX id prefix and uuid suffix.
 */
function deriveRef(stixId: string): { entityType: string; internalId: string } | null {
    const idx = stixId.indexOf('--');
    if (idx < 0) return null;
    const prefix = stixId.slice(0, idx);
    const entityType = STIX_TYPE_TO_INTERNAL[prefix];
    if (!entityType) return null;
    return { entityType, internalId: stixId.slice(idx + 2) };
}

async function importSTIXBundle(bundle: STIXBundle, dryRun: boolean): Promise<ImportResult> {
    const result: ImportResult = {
        bundleId: bundle.id,
        totalObjects: bundle.objects.length,
        imported: { indicators: 0, vulnerabilities: 0, threatActors: 0, malware: 0, relationships: 0, identities: 0, markings: 0, skipped: 0 },
        skippedTypes: {},
        errors: [],
        dryRun,
    };

    const grouped = new Map<string, STIXObject[]>();
    for (const obj of bundle.objects) {
        const list = grouped.get(obj.type) || [];
        list.push(obj);
        grouped.set(obj.type, list);
    }

    // Bookkeeping for the relationship pass: every successfully-persisted
    // object registers its STIX id → internal (entityType, id) here.
    const refMap: RefMap = new Map();

    // Process indicators → IOCs
    for (const indicator of (grouped.get('indicator') || [])) {
        try {
            const parsed = indicator.pattern ? patternToIOC(indicator.pattern) : null;
            if (!parsed) { result.errors.push({ objectId: indicator.id, error: 'Unparseable pattern' }); continue; }

            if (!dryRun) {
                const esc = (s: string) => s.replace(/'/g, "''");
                const severity = stixLabelsToSeverity(indicator.labels);
                const tags = indicator.labels?.length
                    ? `ARRAY[${indicator.labels.map(l => `'${esc(l)}'`).join(',')}]`
                    : 'NULL';
                const rawData = JSON.stringify({ stixId: indicator.id, bundleId: bundle.id }).replace(/'/g, "''");
                const threatType = indicator.indicator_types?.[0] ? `'${esc(indicator.indicator_types[0])}'` : 'NULL';

                const inserted = await db.execute(sql.raw(`
                    INSERT INTO iocs (type, value, source, threat_type, confidence, severity, first_seen, last_seen, tags, raw_data)
                    VALUES ('${parsed.type}', '${esc(parsed.value)}', 'stix-import', ${threatType},
                            ${stixConfidenceToInternal(indicator.confidence)},
                            ${severity ? `'${severity}'` : 'NULL'},
                            ${indicator.valid_from ? `'${indicator.valid_from}'` : 'NULL'},
                            ${indicator.modified ? `'${indicator.modified}'` : 'NULL'},
                            ${tags}, '${rawData}'::jsonb)
                    ON CONFLICT (type, value) DO UPDATE SET
                        confidence = GREATEST(iocs.confidence, EXCLUDED.confidence),
                        last_seen  = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
                        updated_at = NOW()
                    RETURNING id
                `)) as unknown as { id: string }[];
                const internalId = inserted?.[0]?.id;
                if (internalId) refMap.set(indicator.id, { entityType: 'ioc', internalId });
            }
            result.imported.indicators++;
        } catch (err) {
            result.errors.push({ objectId: indicator.id, error: (err as Error).message });
        }
    }

    // Process vulnerabilities → CVEs
    for (const vuln of (grouped.get('vulnerability') || [])) {
        try {
            const cveRef = vuln.external_references?.find(r => r.source_name === 'cve');
            const cveId = cveRef?.external_id || vuln.name || vuln.id;

            if (!dryRun) {
                const esc = (s: string) => s.replace(/'/g, "''");
                const rawData = JSON.stringify({ stixId: vuln.id, name: vuln.name, bundleId: bundle.id }).replace(/'/g, "''");
                const inserted = await db.execute(sql.raw(`
                    INSERT INTO vulnerabilities (cve_id, description, severity, cvss_score, published_date, raw_data)
                    VALUES ('${cveId}', '${esc(vuln.description || '')}',
                            ${vuln.labels?.[0] ? `'${vuln.labels[0]}'` : 'NULL'},
                            ${vuln.x_cvss_score || 'NULL'},
                            ${vuln.created ? `'${vuln.created}'` : 'NULL'},
                            '${rawData}'::jsonb)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description = COALESCE(EXCLUDED.description, vulnerabilities.description),
                        updated_at = NOW()
                    RETURNING id
                `)) as unknown as { id: string }[];
                const internalId = inserted?.[0]?.id;
                if (internalId) refMap.set(vuln.id, { entityType: 'vulnerability', internalId });
            }
            result.imported.vulnerabilities++;
        } catch (err) {
            result.errors.push({ objectId: vuln.id, error: (err as Error).message });
        }
    }

    // Process threat-actors
    for (const actor of (grouped.get('threat-actor') || [])) {
        try {
            if (!dryRun) {
                const esc = (s: string) => s.replace(/'/g, "''");
                const aliases = actor.aliases?.length
                    ? `ARRAY[${actor.aliases.map(a => `'${esc(a)}'`).join(',')}]`
                    : 'NULL';
                const rawData = JSON.stringify({ stixId: actor.id, bundleId: bundle.id }).replace(/'/g, "''");
                const inserted = await db.execute(sql.raw(`
                    INSERT INTO threat_actors (name, description, aliases, sophistication, resource_level, primary_motivation, raw_data)
                    VALUES ('${esc(actor.name || 'Unknown')}', '${esc(actor.description || '')}',
                            ${aliases},
                            ${actor.sophistication ? `'${actor.sophistication}'` : 'NULL'},
                            ${actor.resource_level ? `'${actor.resource_level}'` : 'NULL'},
                            ${actor.primary_motivation ? `'${actor.primary_motivation}'` : 'NULL'},
                            '${rawData}'::jsonb)
                    ON CONFLICT (name) DO UPDATE SET
                        description = COALESCE(EXCLUDED.description, threat_actors.description),
                        updated_at = NOW()
                    RETURNING id
                `)) as unknown as { id: string }[];
                const internalId = inserted?.[0]?.id;
                if (internalId) refMap.set(actor.id, { entityType: 'threat_actor', internalId });
            }
            result.imported.threatActors++;
        } catch (err) {
            result.errors.push({ objectId: actor.id, error: (err as Error).message });
        }
    }

    // Process malware SDOs → malware table
    for (const mw of (grouped.get('malware') || [])) {
        try {
            if (!dryRun) {
                const esc = (s: string) => s.replace(/'/g, "''");
                const aliases = mw.aliases?.length
                    ? `ARRAY[${mw.aliases.map(a => `'${esc(a)}'`).join(',')}]::jsonb`
                    : `'[]'::jsonb`;
                const mwTypes = (mw as unknown as { malware_types?: string[] }).malware_types;
                const malwareTypes = Array.isArray(mwTypes) && mwTypes.length > 0
                    ? `'${JSON.stringify(mwTypes).replace(/'/g, "''")}'::jsonb`
                    : `'[]'::jsonb`;
                const isFamily = typeof mw.is_family === 'boolean' ? `'${mw.is_family}'` : 'NULL';
                const refs = JSON.stringify(mw.external_references || []).replace(/'/g, "''");
                await db.execute(sql.raw(`
                    INSERT INTO malware (stix_id, name, description, malware_types, is_family, aliases, external_references, stix_created, stix_modified, synced_at)
                    VALUES ('${esc(mw.id)}', '${esc(mw.name || 'Unknown')}', '${esc(mw.description || '')}',
                            ${malwareTypes}, ${isFamily}, ${aliases.replace('::jsonb', '')}::jsonb,
                            '${refs}'::jsonb,
                            ${mw.created ? `'${mw.created}'` : 'NULL'},
                            ${mw.modified ? `'${mw.modified}'` : 'NULL'},
                            NOW())
                    ON CONFLICT (stix_id) DO UPDATE SET
                        description = COALESCE(EXCLUDED.description, malware.description),
                        synced_at = NOW(),
                        updated_at = NOW()
                    RETURNING id
                `));
                refMap.set(mw.id, { entityType: 'malware', internalId: stripStixIdPrefix(mw.id) });
            }
            result.imported.malware++;
        } catch (err) {
            result.errors.push({ objectId: mw.id, error: (err as Error).message });
        }
    }

    // Process relationships AFTER all other objects so refMap is populated.
    // STIX `relationship_type` is preserved verbatim — Phase 2 #2 will enum-constrain.
    for (const rel of (grouped.get('relationship') || [])) {
        try {
            const srcRef = rel.source_ref as string | undefined;
            const tgtRef = rel.target_ref as string | undefined;
            const relType = rel.relationship_type;
            if (!srcRef || !tgtRef || !relType) {
                result.errors.push({ objectId: rel.id, error: 'relationship missing source_ref / target_ref / relationship_type' });
                continue;
            }
            // Try to resolve via refMap; fall back to deriving entity type from the STIX prefix
            // and using the bare UUID portion of the STIX id as the foreign-side id.
            const src = refMap.get(srcRef) ?? deriveRef(srcRef);
            const tgt = refMap.get(tgtRef) ?? deriveRef(tgtRef);
            if (!src || !tgt) {
                result.errors.push({ objectId: rel.id, error: `unresolvable refs: ${srcRef} → ${tgtRef}` });
                continue;
            }

            if (!dryRun) {
                const esc = (s: string) => s.replace(/'/g, "''");
                const desc = typeof rel.description === 'string' ? `'${esc(rel.description)}'` : 'NULL';
                const confidence = typeof rel.confidence === 'number'
                    ? Math.max(0, Math.min(100, rel.confidence))
                    : 50;
                await db.execute(sql.raw(`
                    INSERT INTO relationships (source_type, source_id, relationship_type, target_type, target_id, description, confidence, source)
                    VALUES ('${esc(src.entityType)}', '${esc(src.internalId)}', '${esc(relType)}',
                            '${esc(tgt.entityType)}', '${esc(tgt.internalId)}',
                            ${desc}, ${confidence}, 'stix-import')
                `));
            }
            result.imported.relationships++;
        } catch (err) {
            result.errors.push({ objectId: rel.id, error: (err as Error).message });
        }
    }

    // Identity + marking-definition SDOs aren't persisted; we just count them.
    result.imported.identities = (grouped.get('identity') || []).length;
    result.imported.markings = (grouped.get('marking-definition') || []).length;

    // Categorise unsupported types for visibility (rather than the blunt `skipped` counter)
    const handled = new Set(['indicator', 'vulnerability', 'threat-actor', 'malware', 'relationship', 'identity', 'marking-definition']);
    for (const [type, objs] of grouped) {
        if (handled.has(type)) continue;
        result.skippedTypes[type] = objs.length;
        result.imported.skipped += objs.length;
    }

    log.info('STIX bundle imported', {
        bundleId: bundle.id, dryRun,
        indicators: result.imported.indicators,
        vulnerabilities: result.imported.vulnerabilities,
        threatActors: result.imported.threatActors,
        malware: result.imported.malware,
        relationships: result.imported.relationships,
        identities: result.imported.identities,
        markings: result.imported.markings,
        skippedTypes: result.skippedTypes,
        errors: result.errors.length,
    });

    return result;
}

// ============================================================================
// Core Export
// ============================================================================

const STIX_TYPE_MAP: Record<string, string> = {
    ip: 'ipv4-addr', domain: 'domain-name', url: 'url', hash: 'file', email: 'email-addr',
};

async function exportSTIXBundle(
    entityTypes: string[],
    includeRelationships: boolean,
    limit: number,
): Promise<STIXBundle> {
    const objects: STIXObject[] = [{
        type: 'identity',
        id: 'identity--rinjani-analytics',
        spec_version: '2.1',
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
        name: 'Rinjani Analytics CTI Platform',
        identity_class: 'system',
    }];

    if (entityTypes.includes('iocs') || entityTypes.includes('indicators')) {
        const iocResult = await rawQuery<{ id: string; type: string; value: string; source?: string; first_seen?: string; last_seen?: string; created_at?: string; updated_at?: string; tags?: string[]; confidence?: number; threat_type?: string }>(
            `SELECT * FROM iocs ORDER BY last_seen DESC NULLS LAST LIMIT ${limit}`
        );
        for (const ioc of iocResult.rows || []) {
            const stixType = STIX_TYPE_MAP[ioc.type] || 'artifact';
            objects.push({
                type: 'indicator', id: `indicator--${ioc.id}`, spec_version: '2.1',
                created: ioc.first_seen || ioc.created_at, modified: ioc.last_seen || ioc.updated_at,
                name: ioc.value, description: `${ioc.type} indicator from ${ioc.source}`,
                pattern: `[${stixType}:value = '${ioc.value}']`, pattern_type: 'stix',
                valid_from: ioc.first_seen || ioc.created_at,
                labels: ioc.tags || [], confidence: ioc.confidence || 50,
                indicator_types: ioc.threat_type ? [ioc.threat_type] : [],
                created_by_ref: 'identity--rinjani-analytics',
            });
        }
    }

    if (entityTypes.includes('cves') || entityTypes.includes('vulnerabilities')) {
        const cveResult = await rawQuery<{ id: string; cve_id: string; description?: string; severity?: string; cvss_score?: number; published_date?: string; created_at?: string; updated_at?: string }>(
            `SELECT * FROM vulnerabilities ORDER BY published_date DESC NULLS LAST LIMIT ${limit}`
        );
        for (const cve of cveResult.rows || []) {
            objects.push({
                type: 'vulnerability', id: `vulnerability--${cve.id}`, spec_version: '2.1',
                created: cve.published_date || cve.created_at, modified: cve.updated_at,
                name: cve.cve_id, description: cve.description || '',
                labels: cve.severity ? [cve.severity] : [],
                external_references: [{ source_name: 'cve', external_id: cve.cve_id, url: `https://nvd.nist.gov/vuln/detail/${cve.cve_id}` }],
                x_cvss_score: cve.cvss_score, created_by_ref: 'identity--rinjani-analytics',
            });
        }
    }

    if (entityTypes.includes('actors') || entityTypes.includes('threat-actors')) {
        const actorResult = await rawQuery<{ id: string; name: string; description?: string; aliases?: string[]; sophistication?: string; resource_level?: string; primary_motivation?: string; created_at?: string; updated_at?: string }>(
            `SELECT * FROM threat_actors ORDER BY created_at DESC NULLS LAST LIMIT ${limit}`
        );
        for (const actor of actorResult.rows || []) {
            objects.push({
                type: 'threat-actor', id: `threat-actor--${actor.id}`, spec_version: '2.1',
                created: actor.created_at, modified: actor.updated_at,
                name: actor.name, description: actor.description || '',
                aliases: actor.aliases || [], sophistication: actor.sophistication,
                resource_level: actor.resource_level, primary_motivation: actor.primary_motivation,
                created_by_ref: 'identity--rinjani-analytics',
            });
        }
    }

    if (includeRelationships) {
        objects.push(...buildSyntheticRelationships(objects));
    }

    return { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects };
}

// ============================================================================
// Relationships & Validation
// ============================================================================

function buildSyntheticRelationships(objects: STIXObject[]): STIXObject[] {
    const rels: STIXObject[] = [];
    const indicators = objects.filter(o => o.type === 'indicator');
    const actors = objects.filter(o => o.type === 'threat-actor');
    const vulns = objects.filter(o => o.type === 'vulnerability');

    for (const indicator of indicators) {
        for (const actor of actors) {
            const shared = (indicator.labels || []).filter(
                l => (actor.aliases || []).some(a => l.toLowerCase().includes(a.toLowerCase()))
            );
            if (shared.length > 0) {
                rels.push({
                    type: 'relationship', id: `relationship--${crypto.randomUUID()}`, spec_version: '2.1',
                    created: new Date().toISOString(), modified: new Date().toISOString(),
                    relationship_type: 'indicates', source_ref: indicator.id, target_ref: actor.id,
                    description: `Linked via shared labels: ${shared.join(', ')}`,
                });
            }
        }
    }

    for (const vuln of vulns) {
        const cveId = vuln.external_references?.find(r => r.source_name === 'cve')?.external_id;
        if (!cveId) continue;
        for (const indicator of indicators) {
            if (indicator.name?.includes(cveId) || indicator.description?.includes(cveId)) {
                rels.push({
                    type: 'relationship', id: `relationship--${crypto.randomUUID()}`, spec_version: '2.1',
                    created: new Date().toISOString(), modified: new Date().toISOString(),
                    relationship_type: 'exploits', source_ref: indicator.id, target_ref: vuln.id,
                });
            }
        }
    }

    return rels;
}

function validateSTIXBundle(bundle: unknown): { valid: boolean; objectCount: number; typeBreakdown: Record<string, number>; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!bundle || typeof bundle !== 'object') return { valid: false, objectCount: 0, typeBreakdown: {}, errors: ['Input is not a valid object'], warnings };
    const b = bundle as Record<string, unknown>;
    if (b.type !== 'bundle') errors.push('Missing or invalid type (must be "bundle")');
    if (!b.id) errors.push('Missing bundle id');
    if (!Array.isArray(b.objects)) errors.push('Missing or invalid objects array');

    const typeBreakdown: Record<string, number> = {};
    const objects = Array.isArray(b.objects) ? (b.objects as Record<string, unknown>[]) : [];

    for (let i = 0; i < objects.length; i++) {
        const obj = objects[i];
        if (!obj.type) errors.push(`Object at index ${i} missing type`);
        if (!obj.id) errors.push(`Object at index ${i} missing id`);
        typeBreakdown[String(obj.type || 'unknown')] = (typeBreakdown[String(obj.type || 'unknown')] || 0) + 1;
        if (obj.type === 'indicator' && !obj.pattern) warnings.push(`Indicator ${obj.id} missing pattern`);
        if (obj.spec_version && obj.spec_version !== '2.1') warnings.push(`Object ${obj.id} uses spec_version ${obj.spec_version}`);
    }

    return { valid: errors.length === 0, objectCount: objects.length, typeBreakdown, errors, warnings };
}


export default stixPipeline;
