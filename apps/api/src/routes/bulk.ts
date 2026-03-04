/**
 * Bulk Operations API — Barrel
 *
 * Mounts sub-routers:
 *   - bulk/import.ts → IOC JSON & CSV import
 *   - bulk/export.ts → Multi-format export
 *   - bulk/lookup.ts → Bulk lookup & stats
 */

import { Hono } from 'hono';
import { requireAuth } from '../middleware/auth';
import importRoutes from './bulk/import';
import exportRoutes from './bulk/export';
import lookupRoutes from './bulk/lookup';

export const bulkRouter = new Hono();

// Require auth for all bulk operations
bulkRouter.use('*', requireAuth);

// Mount sub-routers
bulkRouter.route('/import', importRoutes);
bulkRouter.route('/export', exportRoutes);
bulkRouter.route('/lookup', lookupRoutes);
bulkRouter.route('/', lookupRoutes);

export default bulkRouter;
