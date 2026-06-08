/**
 * YARA Rule Management Routes
 *
 * REST API for managing and executing YARA-like pattern matching rules.
 *
 *   GET  /v1/yara/rules         → List all loaded rules
 *   GET  /v1/yara/rules/:name   → Get rule details
 *   POST /v1/yara/rules         → Add a new rule
 *   POST /v1/yara/scan          → Scan a value against all rules
 *   POST /v1/yara/batch-scan    → Scan multiple values
 *   POST /v1/yara/scan-sample   → Scan an uploaded file (multipart/form-data, ≤25 MiB)
 *   PUT  /v1/yara/rules/:name/toggle → Toggle rule enabled/disabled
 *   DELETE /v1/yara/rules/:name → Remove a rule
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError } from '../../lib/errors';
import {
    listRules, getRule, addRule, removeRule, toggleRule,
    scanValue, batchScan, scanBytes,
} from '../../services/yaraEngine';
import {
    AddYaraRuleSchema, ToggleYaraRuleSchema, YaraScanSchema, YaraBatchScanSchema,
} from '../../lib/schemas';

const router = new Hono();

// ── List all rules ──────────────────────────────────────────────────

router.get('/yara/rules', requireAuth, (c) => {
    const rules = listRules();
    return c.json({
        success: true,
        data: {
            total: rules.length,
            enabled: rules.filter(r => r.enabled).length,
            rules: rules.map(r => ({
                name: r.name,
                description: r.description,
                severity: r.severity,
                tags: r.tags,
                stringsCount: r.strings.length,
                condition: r.condition,
                enabled: r.enabled,
            })),
        },
    });
});

// ── Get rule detail ─────────────────────────────────────────────────

router.get('/yara/rules/:name', requireAuth, (c) => {
    const name = c.req.param('name')!; // route-guaranteed by :name pattern
    const rule = getRule(name);
    if (!rule) {
        throw new NotFoundError('YARA rule', name);
    }
    return c.json({ success: true, data: rule });
});

// ── Add rule ────────────────────────────────────────────────────────

router.post('/yara/rules', requireAuth, requireRole('admin'), async (c) => {
    const body = AddYaraRuleSchema.parse(await c.req.json());

    const rule = {
        ...body,
        createdAt: new Date().toISOString(),
    };

    await addRule(rule);
    return c.json({ success: true, data: rule }, 201);
});

// ── Toggle rule ─────────────────────────────────────────────────────

router.put('/yara/rules/:name/toggle', requireAuth, requireRole('admin'), async (c) => {
    const name = c.req.param('name')!; // route-guaranteed by :name pattern
    const { enabled } = ToggleYaraRuleSchema.parse(await c.req.json());

    const success = await toggleRule(name, enabled);
    if (!success) {
        throw new NotFoundError('YARA rule', name);
    }

    return c.json({ success: true, message: `Rule "${name}" ${enabled ? 'enabled' : 'disabled'}` });
});

// ── Delete rule ─────────────────────────────────────────────────────

router.delete('/yara/rules/:name', requireAuth, requireRole('admin'), async (c) => {
    const name = c.req.param('name')!; // route-guaranteed by :name pattern
    const deleted = await removeRule(name);

    if (!deleted) {
        throw new NotFoundError('YARA rule', name);
    }
    return c.json({ success: true, message: `Rule "${name}" deleted` });
});

// ── Scan a single value ─────────────────────────────────────────────

router.post('/yara/scan', requireAuth, async (c) => {
    const { value } = YaraScanSchema.parse(await c.req.json());

    const result = scanValue(value);
    return c.json({ success: true, data: result });
});

// ── Batch scan ──────────────────────────────────────────────────────

router.post('/yara/batch-scan', requireAuth, async (c) => {
    const { values } = YaraBatchScanSchema.parse(await c.req.json());

    const result = batchScan(values);
    return c.json({ success: true, data: result });
});

// ── Scan uploaded sample ────────────────────────────────────────────
// Accepts multipart/form-data with a single `file` field, OR a raw body
// (application/octet-stream). Caps the sample at 25 MiB; hash patterns
// and text patterns scan against the raw bytes via latin1 decoding.

const SAMPLE_MAX_BYTES = 25 * 1024 * 1024;

router.post('/yara/scan-sample', requireAuth, async (c) => {
    const ct = c.req.header('content-type') || '';
    let buf: Buffer;
    let filename: string | null = null;

    try {
        if (ct.startsWith('multipart/form-data')) {
            const form = await c.req.parseBody({ all: false });
            const file = form.file;
            if (!file || !(file instanceof File)) {
                throw new ValidationError('multipart upload missing `file` field');
            }
            if (file.size > SAMPLE_MAX_BYTES) {
                throw new ValidationError(`sample exceeds ${SAMPLE_MAX_BYTES} byte limit`);
            }
            buf = Buffer.from(await file.arrayBuffer());
            filename = file.name || null;
        } else {
            const ab = await c.req.arrayBuffer();
            if (ab.byteLength === 0) {
                throw new ValidationError('empty sample body — POST a binary file or multipart upload');
            }
            buf = Buffer.from(ab);
        }
    } catch (err) {
        if (err instanceof ValidationError) throw err;
        throw new ValidationError(`failed to read sample: ${(err as Error).message}`);
    }

    if (buf.length > SAMPLE_MAX_BYTES) {
        throw new ValidationError(`sample exceeds ${SAMPLE_MAX_BYTES} byte limit`);
    }

    const result = scanBytes(buf);
    return c.json({
        success: true,
        data: {
            ...result,
            input: filename ?? `<binary:${buf.length} bytes>`,
            sample: { filename, sizeBytes: buf.length },
        },
    });
});

export default router;
