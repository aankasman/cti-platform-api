/**
 * Nexus Intelligence Routes
 *
 * Web intelligence discovery endpoints (search, scrape, websets, providers).
 * All handler logic has been decomposed into sub-modules under ./nexus/.
 */

import { Hono } from 'hono';
import searchRoutes from './nexus/search';
import scrapeRoutes from './nexus/scrape';
import websetRoutes from './nexus/websets';
import providerRoutes from './nexus/providers';

const nexusRoutes = new Hono();

// Search (real-time web + CTI)
nexusRoutes.route('/', searchRoutes);

// Deep scrape
nexusRoutes.route('/', scrapeRoutes);

// Websets, webhooks, bootstrap
nexusRoutes.route('/', websetRoutes);

// Providers, health, extract-iocs
nexusRoutes.route('/', providerRoutes);

export default nexusRoutes;
