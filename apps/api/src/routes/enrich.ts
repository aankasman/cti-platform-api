/**
 * Enrichment Routes — Barrel
 *
 * Mounts sub-routers:
 *   - enrich/ip.ts     → IP enrichment
 *   - enrich/domain.ts → Domain + VirusTotal enrichment
 *   - enrich/hash.ts   → File hash enrichment
 *   - enrich/bulk.ts   → Bulk enrichment
 */

import { Hono } from 'hono';
import ipRoutes from './enrich/ip';
import domainRoutes from './enrich/domain';
import hashRoutes from './enrich/hash';
import bulkEnrichRoutes from './enrich/bulk';

const enrich = new Hono();

enrich.route('/ip', ipRoutes);
enrich.route('/domain', domainRoutes);
enrich.route('/hash', hashRoutes);
enrich.route('/bulk', bulkEnrichRoutes);

export default enrich;
