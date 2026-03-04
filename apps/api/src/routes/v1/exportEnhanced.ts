/**
 * Enhanced Export Routes (IntelOwl/MISP/TheHive inspired)
 *
 * Multi-format export pipeline:
 *   - MISP event format
 *   - Suricata/Snort IDS rules
 *   - Intelligence reports (Markdown/HTML)
 *
 * Mounts at: /v1/export/*
 */

import { Hono } from 'hono';
import { requireAuth } from '../../middleware/auth';
import { MISPExportSchema, RuleExportSchema, ReportExportSchema } from '../../lib/schemas';
import { rawQuery, sql } from '@rinjani/db';
import { createLogger } from '../../lib/logger';

const log = createLogger('Export');
const exportRoutes = new Hono();
exportRoutes.use('*', requireAuth);

// ============================================================================
// MISP Event Format Export
// ============================================================================

interface MISPAttribute {
    type: string;
    category: string;
    value: string;
    comment: string;
    to_ids: boolean;
    timestamp: string;
    Tag?: Array<{ name: string; colour: string }>;
}

/** POST /v1/export/misp — Export as MISP event format */
exportRoutes.post('/export/misp', async (c) => {
    const body = MISPExportSchema.parse(await c.req.json().catch(() => ({})));
    const attributes: MISPAttribute[] = [];

    if (body.entityTypes.includes('iocs')) {
        let whereClause = '1=1';
        if (body.dateFrom) whereClause += ` AND created_at >= '${body.dateFrom}'`;
        if (body.dateTo) whereClause += ` AND created_at <= '${body.dateTo}'`;

        const result = await rawQuery<{
            id: string; type: string; value: string; threat_type: string | null;
            confidence: number | null; severity: string | null; tags: string[] | null;
            first_seen: string | null; source: string | null;
        }>(sql.raw(`SELECT id, type, value, threat_type, confidence, severity, tags, first_seen, source FROM iocs WHERE ${whereClause} ORDER BY created_at DESC LIMIT ${body.limit}`));

        const MISP_TYPE_MAP: Record<string, string> = {
            ip: 'ip-dst', domain: 'domain', url: 'url', hash: 'md5', email: 'email-src',
        };

        for (const ioc of (result.rows || [])) {
            const tags: Array<{ name: string; colour: string }> = [];
            if (ioc.severity) tags.push({ name: `severity:${ioc.severity}`, colour: ioc.severity === 'critical' ? '#FF0000' : '#FFA500' });
            tags.push({ name: `tlp:${body.tlp}`, colour: body.tlp === 'red' ? '#FF0000' : '#33FF33' });

            attributes.push({
                type: MISP_TYPE_MAP[ioc.type] || ioc.type,
                category: 'Network activity',
                value: ioc.value,
                comment: `Source: ${ioc.source || 'unknown'}, Confidence: ${ioc.confidence || 'N/A'}`,
                to_ids: true,
                timestamp: ioc.first_seen || new Date().toISOString(),
                Tag: tags,
            });
        }
    }

    const mispEvent = {
        Event: {
            info: `Rinjani CTI Export — ${new Date().toISOString()}`,
            date: new Date().toISOString().split('T')[0],
            threat_level_id: '2',
            analysis: '2',
            distribution: body.tlp === 'white' ? '3' : body.tlp === 'green' ? '2' : '1',
            Tag: [{ name: `tlp:${body.tlp}`, colour: body.tlp === 'red' ? '#FF0000' : '#33FF33' }],
            Attribute: attributes,
        },
    };

    log.info('MISP format export', { attributeCount: attributes.length, tlp: body.tlp });
    return c.json({ success: true, data: mispEvent });
});

// ============================================================================
// IDS Rule Export (Suricata/Snort)
// ============================================================================

/** POST /v1/export/rules — Export IOCs as IDS rules */
exportRoutes.post('/export/rules', async (c) => {
    const body = RuleExportSchema.parse(await c.req.json().catch(() => ({})));
    const typeList = body.iocTypes.map(t => `'${t}'`).join(',');
    let whereClause = `type IN (${typeList})`;
    if (body.severity) whereClause += ` AND severity = '${body.severity}'`;

    const result = await rawQuery<{
        id: string; type: string; value: string; threat_type: string | null;
        source: string | null;
    }>(sql.raw(`SELECT id, type, value, threat_type, source FROM iocs WHERE ${whereClause} ORDER BY created_at DESC LIMIT ${body.limit}`));

    const rules: string[] = [];
    let sid = body.sid_start;
    const header = body.format === 'suricata'
        ? `# Rinjani CTI — Suricata Rules\n# Generated: ${new Date().toISOString()}\n# Total IOCs: ${(result.rows || []).length}\n`
        : `# Rinjani CTI — Snort Rules\n# Generated: ${new Date().toISOString()}\n# Total IOCs: ${(result.rows || []).length}\n`;
    rules.push(header);

    for (const ioc of (result.rows || [])) {
        const msg = `Rinjani CTI: ${ioc.type} ${ioc.value} [${ioc.threat_type || 'unknown'}]`;
        const ref = `reference:url,rinjani.local/iocs/${ioc.id}`;

        if (ioc.type === 'ip') {
            rules.push(`${body.action} ip ${ioc.value} any -> $HOME_NET any (msg:"${msg}"; ${ref}; sid:${sid++}; rev:1;)`);
        } else if (ioc.type === 'domain') {
            rules.push(`${body.action} dns $HOME_NET any -> any any (msg:"${msg}"; dns.query; content:"${ioc.value}"; nocase; ${ref}; sid:${sid++}; rev:1;)`);
        } else if (ioc.type === 'url') {
            const urlValue = ioc.value.replace(/"/g, '');
            rules.push(`${body.action} http $HOME_NET any -> $EXTERNAL_NET any (msg:"${msg}"; content:"${urlValue}"; http.uri; nocase; ${ref}; sid:${sid++}; rev:1;)`);
        } else if (ioc.type === 'hash') {
            rules.push(`# Hash IOC (file inspection rule): ${ioc.value}`);
        }
    }

    log.info('IDS rule export', { format: body.format, ruleCount: rules.length - 1 });
    return c.json({
        success: true,
        data: {
            format: body.format,
            ruleCount: rules.length - 1, // header doesn't count
            rules: rules.join('\n'),
        },
    }, 200, {
        'Content-Disposition': `attachment; filename="rinjani_${body.format}_rules_${Date.now()}.rules"`,
    });
});

// ============================================================================
// Intelligence Report Export
// ============================================================================

/** POST /v1/export/report — Generate intelligence report */
exportRoutes.post('/export/report', async (c) => {
    const body = ReportExportSchema.parse(await c.req.json().catch(() => ({})));
    const sections: string[] = [];

    sections.push(`# Rinjani CTI Intelligence Report`);
    sections.push(`**Generated:** ${new Date().toISOString()}`);
    sections.push(`**Format:** ${body.format} | **Scope:** ${body.scope}`);
    if (body.dateFrom || body.dateTo) {
        sections.push(`**Date Range:** ${body.dateFrom || '—'} to ${body.dateTo || '—'}`);
    }
    sections.push('');

    // IOC summary
    if (body.entityTypes.includes('iocs')) {
        let whereClause = '1=1';
        if (body.dateFrom) whereClause += ` AND created_at >= '${body.dateFrom}'`;
        if (body.dateTo) whereClause += ` AND created_at <= '${body.dateTo}'`;

        const stats = await rawQuery<{ type: string; severity: string; cnt: string }>(
            sql.raw(`SELECT type, COALESCE(severity,'unknown') AS severity, COUNT(*) AS cnt FROM iocs WHERE ${whereClause} GROUP BY type, severity ORDER BY cnt DESC LIMIT 50`)
        );
        const iocCount = await rawQuery<{ total: string }>(
            sql.raw(`SELECT COUNT(*) AS total FROM iocs WHERE ${whereClause}`)
        );

        sections.push('## Indicators of Compromise (IOCs)');
        sections.push(`**Total IOCs:** ${iocCount.rows?.[0]?.total || 0}`);
        sections.push('');
        sections.push('| Type | Severity | Count |');
        sections.push('|------|----------|-------|');
        for (const row of (stats.rows || [])) {
            sections.push(`| ${row.type} | ${row.severity} | ${row.cnt} |`);
        }
        sections.push('');
    }

    // Vulnerability summary
    if (body.entityTypes.includes('vulnerabilities')) {
        const vulnStats = await rawQuery<{ severity: string; cnt: string }>(
            sql.raw(`SELECT COALESCE(severity,'unknown') AS severity, COUNT(*) AS cnt FROM vulnerabilities GROUP BY severity ORDER BY cnt DESC`)
        );

        sections.push('## Vulnerabilities');
        sections.push('');
        sections.push('| Severity | Count |');
        sections.push('|----------|-------|');
        for (const row of (vulnStats.rows || [])) {
            sections.push(`| ${row.severity} | ${row.cnt} |`);
        }
        sections.push('');
    }

    const report = sections.join('\n');
    log.info('Intelligence report generated', { format: body.format, scope: body.scope });
    return c.json({
        success: true,
        data: {
            format: body.format,
            content: report,
        },
    });
});

export default exportRoutes;
