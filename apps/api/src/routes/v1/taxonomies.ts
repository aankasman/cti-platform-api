/**
 * Taxonomy & Tag Namespace System (MISP inspired)
 *
 * Structured tag management with namespaced taxonomies:
 *   - Built-in: TLP, Admiralty Scale, threat types, sectors
 *   - Custom: User-defined taxonomies with validation
 *
 * Mounts at: /v1/taxonomies/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { CreateTaxonomySchema, AddTaxonomyTagSchema } from '../../lib/schemas';
import { rawQuery, sql } from '@rinjani/db';
import { createLogger } from '../../lib/logger';

const log = createLogger('Taxonomies');
const taxonomyRoutes = new Hono();
taxonomyRoutes.use('*', requireAuth);

// ============================================================================
// Built-in Taxonomies
// ============================================================================

interface Taxonomy {
    namespace: string;
    name: string;
    description: string;
    exclusive: boolean;
    builtin: boolean;
    tags: TaxonomyTag[];
}

interface TaxonomyTag {
    tag: string;
    description: string;
    colour?: string;
    numericValue?: number;
}

const BUILTIN_TAXONOMIES: Taxonomy[] = [
    {
        namespace: 'tlp', name: 'Traffic Light Protocol', description: 'Information sharing classification',
        exclusive: true, builtin: true,
        tags: [
            { tag: 'white', description: 'Unlimited disclosure', colour: '#FFFFFF' },
            { tag: 'green', description: 'Community-wide sharing', colour: '#33FF33' },
            { tag: 'amber', description: 'Limited disclosure', colour: '#FFC000' },
            { tag: 'amber+strict', description: 'Only within organization', colour: '#FF8C00' },
            { tag: 'red', description: 'Named recipients only', colour: '#FF0000' },
        ],
    },
    {
        namespace: 'admiralty-scale', name: 'Admiralty Code', description: 'NATO source reliability and information credibility rating',
        exclusive: false, builtin: true,
        tags: [
            { tag: 'source-reliability:a', description: 'Completely Reliable', numericValue: 1 },
            { tag: 'source-reliability:b', description: 'Usually Reliable', numericValue: 2 },
            { tag: 'source-reliability:c', description: 'Fairly Reliable', numericValue: 3 },
            { tag: 'source-reliability:d', description: 'Not Usually Reliable', numericValue: 4 },
            { tag: 'source-reliability:e', description: 'Unreliable', numericValue: 5 },
            { tag: 'source-reliability:f', description: 'Cannot Be Judged', numericValue: 6 },
            { tag: 'information-credibility:1', description: 'Confirmed', numericValue: 1 },
            { tag: 'information-credibility:2', description: 'Probably True', numericValue: 2 },
            { tag: 'information-credibility:3', description: 'Possibly True', numericValue: 3 },
            { tag: 'information-credibility:4', description: 'Doubtful', numericValue: 4 },
            { tag: 'information-credibility:5', description: 'Improbable', numericValue: 5 },
            { tag: 'information-credibility:6', description: 'Cannot Be Judged', numericValue: 6 },
        ],
    },
    {
        namespace: 'confidence-level', name: 'Confidence Level', description: 'Analytic confidence rating for intelligence',
        exclusive: true, builtin: true,
        tags: [
            { tag: 'high', description: 'High confidence — multiple corroborating sources', colour: '#00CC00', numericValue: 90 },
            { tag: 'medium', description: 'Medium confidence — plausible with partial corroboration', colour: '#FFA500', numericValue: 60 },
            { tag: 'low', description: 'Low confidence — single source or uncorroborated', colour: '#FF6347', numericValue: 30 },
            { tag: 'none', description: 'No assessed confidence', colour: '#999999', numericValue: 0 },
        ],
    },
    {
        namespace: 'sector', name: 'Industry Sectors', description: 'Target industry sector classification',
        exclusive: false, builtin: true,
        tags: [
            { tag: 'finance', description: 'Financial services and banking' },
            { tag: 'government', description: 'Government and public sector' },
            { tag: 'healthcare', description: 'Healthcare and pharmaceutical' },
            { tag: 'energy', description: 'Energy and utilities' },
            { tag: 'technology', description: 'Technology and telecommunications' },
            { tag: 'defense', description: 'Defense and military' },
            { tag: 'education', description: 'Education and research' },
            { tag: 'retail', description: 'Retail and e-commerce' },
            { tag: 'manufacturing', description: 'Manufacturing and industrial' },
            { tag: 'transportation', description: 'Transportation and logistics' },
        ],
    },
];

// ============================================================================
// Ensure custom_taxonomies table
// ============================================================================

let _taxTableReady: Promise<void> | null = null;
async function ensureTaxonomyTable(): Promise<void> {
    if (_taxTableReady) return _taxTableReady;
    _taxTableReady = (async () => {
        try {
            await rawQuery(`
                CREATE TABLE IF NOT EXISTS custom_taxonomies (
                    namespace TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    exclusive BOOLEAN DEFAULT FALSE,
                    tags JSONB DEFAULT '[]',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
            `);
            log.info('custom_taxonomies table ready');
        } catch (err) {
            log.warn('Failed to ensure custom_taxonomies table', { error: (err as Error).message });
        }
    })();
    return _taxTableReady;
}

// ============================================================================
// Routes
// ============================================================================

/** GET /v1/taxonomies — List all taxonomies (built-in + custom) */
taxonomyRoutes.get('/taxonomies', async (c) => {
    await ensureTaxonomyTable();
    const result = await rawQuery<{
        namespace: string; name: string; description: string;
        exclusive: boolean; tags: TaxonomyTag[];
    }>('SELECT * FROM custom_taxonomies ORDER BY namespace');

    const customTaxonomies: Taxonomy[] = (result.rows || []).map(r => ({
        ...r,
        builtin: false,
    }));

    return c.json({
        success: true,
        data: {
            taxonomies: [...BUILTIN_TAXONOMIES, ...customTaxonomies],
            total: BUILTIN_TAXONOMIES.length + customTaxonomies.length,
        },
    });
});

/** GET /v1/taxonomies/:namespace — Get a specific taxonomy */
taxonomyRoutes.get('/taxonomies/:namespace', async (c) => {
    const { namespace } = c.req.param();

    // Check built-in first
    const builtin = BUILTIN_TAXONOMIES.find(t => t.namespace === namespace);
    if (builtin) return c.json({ success: true, data: builtin });

    // Check custom
    await ensureTaxonomyTable();
    const esc = (s: string) => s.replace(/'/g, "''");
    const result = await rawQuery<{
        namespace: string; name: string; description: string;
        exclusive: boolean; tags: TaxonomyTag[];
    }>(sql.raw(`SELECT * FROM custom_taxonomies WHERE namespace = '${esc(namespace)}'`));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('Taxonomy', namespace);
    return c.json({ success: true, data: { ...row, builtin: false } });
});

/** POST /v1/taxonomies — Create a custom taxonomy */
taxonomyRoutes.post('/taxonomies', requireRole('admin', 'analyst'), async (c) => {
    const body = CreateTaxonomySchema.parse(await c.req.json().catch(() => ({})));

    // Check for collision
    if (BUILTIN_TAXONOMIES.some(t => t.namespace === body.namespace)) {
        return c.json({ success: false, error: 'Cannot override built-in taxonomy' }, 409);
    }

    await ensureTaxonomyTable();
    const esc = (s: string) => s.replace(/'/g, "''");
    await rawQuery(sql.raw(`
        INSERT INTO custom_taxonomies (namespace, name, description, exclusive)
        VALUES ('${esc(body.namespace)}', '${esc(body.name)}', '${esc(body.description)}', ${body.exclusive})
        ON CONFLICT (namespace) DO UPDATE SET
            name = EXCLUDED.name,
            description = EXCLUDED.description,
            exclusive = EXCLUDED.exclusive,
            updated_at = NOW()
    `));

    log.info('Custom taxonomy created', { namespace: body.namespace });
    return c.json({
        success: true,
        data: { namespace: body.namespace, name: body.name, description: body.description, exclusive: body.exclusive, builtin: false, tags: [] },
    }, 201);
});

/** POST /v1/taxonomies/:namespace/tag — Add tag to taxonomy */
taxonomyRoutes.post('/taxonomies/:namespace/tag', requireRole('admin', 'analyst'), async (c) => {
    const { namespace } = c.req.param();
    const body = AddTaxonomyTagSchema.parse(await c.req.json().catch(() => ({})));

    if (BUILTIN_TAXONOMIES.some(t => t.namespace === namespace)) {
        return c.json({ success: false, error: 'Cannot modify built-in taxonomy tags' }, 403);
    }

    await ensureTaxonomyTable();
    const esc = (s: string) => s.replace(/'/g, "''");
    const tagObj = JSON.stringify(body).replace(/'/g, "''");
    await rawQuery(sql.raw(`
        UPDATE custom_taxonomies
        SET tags = tags || '${tagObj}'::jsonb,
            updated_at = NOW()
        WHERE namespace = '${esc(namespace)}'
    `));

    log.info('Taxonomy tag added', { namespace, tag: body.tag });
    return c.json({ success: true, data: body }, 201);
});

/** DELETE /v1/taxonomies/:namespace/tag/:tag — Remove tag from taxonomy */
taxonomyRoutes.delete('/taxonomies/:namespace/tag/:tag', requireRole('admin'), async (c) => {
    const { namespace, tag } = c.req.param();

    if (BUILTIN_TAXONOMIES.some(t => t.namespace === namespace)) {
        return c.json({ success: false, error: 'Cannot modify built-in taxonomy tags' }, 403);
    }

    await ensureTaxonomyTable();
    const esc = (s: string) => s.replace(/'/g, "''");
    await rawQuery(sql.raw(`
        UPDATE custom_taxonomies
        SET tags = (
            SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
            FROM jsonb_array_elements(tags) elem
            WHERE elem->>'tag' != '${esc(tag)}'
        ),
        updated_at = NOW()
        WHERE namespace = '${esc(namespace)}'
    `));

    log.info('Taxonomy tag removed', { namespace, tag });
    return c.json({ success: true, data: { namespace, tag, deleted: true } });
});

/** DELETE /v1/taxonomies/:namespace — Delete custom taxonomy */
taxonomyRoutes.delete('/taxonomies/:namespace', requireRole('admin'), async (c) => {
    const { namespace } = c.req.param();

    if (BUILTIN_TAXONOMIES.some(t => t.namespace === namespace)) {
        return c.json({ success: false, error: 'Cannot delete built-in taxonomy' }, 403);
    }

    await ensureTaxonomyTable();
    const esc = (s: string) => s.replace(/'/g, "''");
    await rawQuery(sql.raw(`DELETE FROM custom_taxonomies WHERE namespace = '${esc(namespace)}'`));

    log.info('Custom taxonomy deleted', { namespace });
    return c.json({ success: true, data: { namespace, deleted: true } });
});

export default taxonomyRoutes;
