/**
 * Advanced Search Routes — Barrel
 *
 * Mounts sub-routers:
 *   - search/iocs.ts            → IOC search + aggregations
 *   - search/vulnerabilities.ts → Vulnerability search
 *
 * Schemas defined in search/schemas.ts
 */

import { Hono } from 'hono';
import iocSearch from './search/iocs';
import vulnSearch from './search/vulnerabilities';

const search = new Hono();

search.route('/iocs', iocSearch);
search.route('/vulnerabilities', vulnSearch);

export default search;
