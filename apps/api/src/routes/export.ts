/**
 * Export Routes — Barrel
 *
 * Provides data export capabilities in multiple formats:
 * - CSV (Excel-compatible)
 * - JSON (structured)
 * - STIX 2.1 (standard threat intelligence format)
 */

import { Hono } from 'hono';
import csvRoutes from './export/csv';
import jsonRoutes from './export/json';
import stixRoutes from './export/stix';

const exportRoutes = new Hono();

exportRoutes.route('/', csvRoutes);
exportRoutes.route('/', jsonRoutes);
exportRoutes.route('/', stixRoutes);

export default exportRoutes;
