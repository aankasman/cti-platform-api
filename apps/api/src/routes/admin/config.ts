/**
 * Admin Config Management Routes
 *
 * Auth-guarded admin versions of the config CRUD endpoints.
 * Wraps the existing configStore with requireAuth + requireRole('admin').
 * Also provides a general-purpose settings key-value store.
 *
 * Mounts at: /admin/config/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { AddFeedSchema, AddApiKeySchema, AddServiceSchema, UpdateSettingSchema } from '../../lib/schemas';
import { NotFoundError, ValidationError } from '../../lib/errors';
import {
    // Feeds
    listFeeds, updateFeed, addCustomFeed, deleteCustomFeed,
    // API Keys
    listApiKeys, updateApiKey, addCustomApiKey, deleteCustomApiKey, testApiKey,
    // Services
    listServices, updateService, addCustomService, deleteCustomService,
    // General config
    getConfig, setConfig, deleteConfig,
} from '../../services/configStore';

const router = new Hono();

// ============================================================================
// Feeds CRUD
// ============================================================================

router.get('/config/feeds', requireAuth, requireRole('admin'), async (c) => {
    const feeds = await listFeeds();
    return c.json({ success: true, data: feeds });
});

router.post('/config/feeds', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json();
    const data = AddFeedSchema.parse(body);
    const feed = await addCustomFeed({
        name: data.name,
        source: data.source,
        description: data.description,
        cron: data.cron,
        enabled: data.enabled,
        category: data.category,
        url: data.url,
        format: data.format,
        authHeader: data.authHeader,
        authKeyRef: data.authKeyRef,
        requiresApiKey: data.requiresApiKey,
    });
    return c.json({ success: true, data: feed }, 201);
});

router.put('/config/feeds/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const body = await c.req.json();
    const updated = await updateFeed(id, {
        cron: body.cron, enabled: body.enabled, name: body.name,
        description: body.description, url: body.url, format: body.format,
        authHeader: body.authHeader, authKeyRef: body.authKeyRef,
        category: body.category, source: body.source,
    });
    if (!updated) throw new NotFoundError('Feed', id);
    return c.json({ success: true, data: updated });
});

router.delete('/config/feeds/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const ok = await deleteCustomFeed(id);
    if (!ok) throw new NotFoundError('Feed', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// ============================================================================
// API Keys CRUD
// ============================================================================

router.get('/config/api-keys', requireAuth, requireRole('admin'), async (c) => {
    const keys = await listApiKeys();
    return c.json({ success: true, data: keys });
});

router.post('/config/api-keys', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json();
    const data = AddApiKeySchema.parse(body);
    const slot = await addCustomApiKey({
        name: data.name,
        provider: data.provider,
        envVar: data.envVar,
        testEndpoint: data.testEndpoint,
        authHeaderName: data.authHeaderName,
    }, data.value);
    return c.json({ success: true, data: slot }, 201);
});

router.put('/config/api-keys/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const { value } = await c.req.json();
    if (!value || typeof value !== 'string') throw new ValidationError('Missing value');
    const ok = await updateApiKey(id, value.trim());
    if (!ok) throw new NotFoundError('API key', id);
    return c.json({ success: true, data: { id, updated: true } });
});

router.delete('/config/api-keys/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const ok = await deleteCustomApiKey(id);
    if (!ok) throw new NotFoundError('API key', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

router.post('/config/api-keys/:id/test', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const result = await testApiKey(id);
    return c.json({ success: true, data: result });
});

// ============================================================================
// Services CRUD
// ============================================================================

router.get('/config/services', requireAuth, requireRole('admin'), async (c) => {
    const services = await listServices();
    return c.json({ success: true, data: services });
});

router.post('/config/services', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json();
    const data = AddServiceSchema.parse(body);
    const svc = await addCustomService({ name: data.name, envVars: data.envVars }, data.values);
    return c.json({ success: true, data: svc }, 201);
});

router.put('/config/services/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const updates = await c.req.json();
    const ok = await updateService(id, updates);
    if (!ok) throw new NotFoundError('Service', id);
    return c.json({ success: true, data: { id, updated: true } });
});

router.delete('/config/services/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const ok = await deleteCustomService(id);
    if (!ok) throw new NotFoundError('Service', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// ============================================================================
// General Settings KV
// ============================================================================

router.get('/config/settings', requireAuth, requireRole('admin'), async (c) => {
    // Config-store keys
    const keys = [
        'LOG_LEVEL', 'FEED_SYNC_ENABLED', 'ENRICHMENT_ENABLED',
        'AI_ANALYSIS_ENABLED', 'NEO4J_SYNC_ENABLED', 'RATE_LIMIT_WINDOW',
        'RATE_LIMIT_MAX', 'SESSION_TIMEOUT_MINUTES',
        'EMBEDDING_PROVIDER', 'EMBEDDING_MODEL',
    ];

    const settings: Record<string, string | null> = {};
    for (const key of keys) {
        settings[key] = await getConfig(key);
    }

    // Also expose AI/LLM env vars (masked) so the dashboard can show provider status
    const aiEnvKeys = [
        'GOOGLE_API_KEY', 'GEMINI_API_KEY', 'OPENROUTER_API_KEY',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
        'OLLAMA_URL', 'OLLAMA_MODEL',
        'AI_DEFAULT_MODEL',
    ];
    for (const key of aiEnvKeys) {
        const val = process.env[key];
        settings[key] = val ? `${val.slice(0, 4)}••••${val.slice(-4)}` : null;
    }

    return c.json({ success: true, data: settings });
});

router.put('/config/settings/:key', requireAuth, requireRole('admin'), async (c) => {
    const { key } = c.req.param();
    const body = await c.req.json();
    const { value } = UpdateSettingSchema.parse(body);
    await setConfig(key, String(value));
    return c.json({ success: true, data: { key, value: String(value), updated: true } });
});

router.delete('/config/settings/:key', requireAuth, requireRole('admin'), async (c) => {
    const { key } = c.req.param();
    await deleteConfig(key);
    return c.json({ success: true, data: { key, deleted: true } });
});

export default router;
