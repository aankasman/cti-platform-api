/**
 * Phase 4 #1 — extra notification channel adapters + rule routing.
 *
 * `services/notifications.ts` already ships Slack + Email + the
 * dashboard bell. This module adds Teams, Discord, PagerDuty so the
 * standard SOC toolchain is covered, plus a small rule DSL so an
 * operator can wire "severity=critical AND inKev=true → PagerDuty"
 * without code changes.
 *
 * Each adapter mirrors the `sendSlackNotification` signature: takes a
 * webhook URL and a typed payload, returns {success, error?}. All HTTP
 * failures are caught and reported as `{success: false, error}` —
 * never thrown — so the caller can fan-out without try/catch.
 */
import type { NotificationPayload } from './notifications';
import { createLogger } from '../lib/logger';

const log = createLogger('NotificationChannels');

export type ChannelKind = 'slack' | 'teams' | 'discord' | 'pagerduty' | 'email' | 'webhook';

export interface ChannelResult { success: boolean; error?: string }

const SEVERITY_COLOR: Record<string, number> = {
    critical: 0xef4444,
    high: 0xf59e0b,
    medium: 0x3b82f6,
    low: 0x10b981,
};
const SEVERITY_HEX: Record<string, string> = {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#3b82f6',
    low: '#10b981',
};

// ============================================================================
// Microsoft Teams — Incoming Webhook (MessageCard format)
// ============================================================================

export async function sendTeamsNotification(webhookUrl: string, payload: NotificationPayload): Promise<ChannelResult> {
    try {
        const themeColor = SEVERITY_HEX[payload.severity]?.slice(1) ?? '6b7280';
        const card = {
            '@type': 'MessageCard',
            '@context': 'https://schema.org/extensions',
            themeColor,
            summary: payload.title,
            title: payload.title,
            text: payload.message,
            sections: [{
                facts: [
                    { name: 'Type', value: payload.type.toUpperCase() },
                    { name: 'Severity', value: payload.severity.toUpperCase() },
                    { name: 'Source', value: 'Rinjani CTI Platform' },
                ],
            }],
        };
        const r = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(card),
        });
        if (!r.ok) return { success: false, error: `Teams webhook HTTP ${r.status}` };
        return { success: true };
    } catch (err) {
        return { success: false, error: (err as Error).message };
    }
}

// ============================================================================
// Discord — Webhook embed
// ============================================================================

export async function sendDiscordNotification(webhookUrl: string, payload: NotificationPayload): Promise<ChannelResult> {
    try {
        const embed = {
            title: payload.title.slice(0, 256),         // Discord cap
            description: payload.message.slice(0, 4096),
            color: SEVERITY_COLOR[payload.severity] ?? 0x6b7280,
            fields: [
                { name: 'Type', value: payload.type.toUpperCase(), inline: true },
                { name: 'Severity', value: payload.severity.toUpperCase(), inline: true },
            ],
            footer: { text: 'Rinjani CTI Platform' },
            timestamp: new Date().toISOString(),
        };
        const r = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: 'Rinjani CTI', embeds: [embed] }),
        });
        if (!r.ok) return { success: false, error: `Discord webhook HTTP ${r.status}` };
        return { success: true };
    } catch (err) {
        return { success: false, error: (err as Error).message };
    }
}

// ============================================================================
// PagerDuty — Events API v2 (Enqueue Event)
//
// The "webhook URL" here is actually the PD routing key (integration key).
// We POST to the global PD Events API endpoint and pass the key in the
// body — that's the standard PD shape.
// ============================================================================

const PD_EVENTS_API = 'https://events.pagerduty.com/v2/enqueue';

// PD's severity vocabulary is critical | error | warning | info
const PD_SEVERITY: Record<string, 'critical' | 'error' | 'warning' | 'info'> = {
    critical: 'critical',
    high: 'error',
    medium: 'warning',
    low: 'info',
};

export async function sendPagerDutyNotification(routingKey: string, payload: NotificationPayload): Promise<ChannelResult> {
    try {
        // PD requires a stable dedup_key for grouping; derive one from the
        // payload data so retries collapse into a single incident.
        const dedupKey = (payload.data?.dedupKey as string | undefined)
            ?? `${payload.type}:${payload.severity}:${payload.title.slice(0, 60)}`;

        const body = {
            routing_key: routingKey,
            event_action: 'trigger',
            dedup_key: dedupKey,
            payload: {
                summary: payload.title,
                severity: PD_SEVERITY[payload.severity] ?? 'warning',
                source: 'rinjani-cti',
                component: payload.type,
                custom_details: {
                    message: payload.message,
                    ...(payload.data ?? {}),
                },
            },
        };
        const r = await fetch(PD_EVENTS_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!r.ok) {
            const txt = await r.text().catch(() => '');
            return { success: false, error: `PagerDuty Events API HTTP ${r.status}: ${txt.slice(0, 200)}` };
        }
        return { success: true };
    } catch (err) {
        return { success: false, error: (err as Error).message };
    }
}

// ============================================================================
// Notification rule DSL
// ============================================================================

export interface NotificationRule {
    /** Human-readable rule label. */
    name: string;
    enabled?: boolean;
    match: {
        /** Match if payload.severity is in this list. */
        severityIn?: Array<'critical' | 'high' | 'medium' | 'low'>;
        /** Match if payload.type is in this list. */
        typeIn?: Array<'ioc' | 'vulnerability' | 'threat_actor' | 'alert'>;
        /**
         * Match if every key/value pair in `requireData` is === to
         * payload.data[key]. Boolean fields (`inKev`, `revoked`, etc.)
         * are the typical use case — supports strings + numbers too.
         */
        requireData?: Record<string, string | number | boolean>;
    };
    /**
     * Channels to fire when the rule matches. Each entry pairs a
     * channel kind with its target (webhook URL, email, or PD key).
     */
    channels: Array<{ channel: ChannelKind; target: string }>;
}

/**
 * Return true iff every clause in the rule's `match` block is satisfied
 * by the payload. An undefined / empty clause is vacuously true so
 * operators can leave fields off when they don't care.
 */
export function evaluateNotificationRule(rule: NotificationRule, payload: NotificationPayload): boolean {
    if (rule.enabled === false) return false;
    const m = rule.match;

    if (m.severityIn && m.severityIn.length > 0 && !m.severityIn.includes(payload.severity)) return false;
    if (m.typeIn && m.typeIn.length > 0 && !m.typeIn.includes(payload.type)) return false;

    if (m.requireData) {
        const d = payload.data ?? {};
        for (const [k, v] of Object.entries(m.requireData)) {
            if (d[k] !== v) return false;
        }
    }
    return true;
}

/**
 * Apply a list of rules to a payload and return every channel target
 * that should fire. Returns deduplicated `(channel, target)` pairs so a
 * single high-priority alert covered by two rules doesn't double-fire.
 */
export function resolveRuleChannels(rules: NotificationRule[], payload: NotificationPayload): Array<{ channel: ChannelKind; target: string }> {
    const seen = new Set<string>();
    const out: Array<{ channel: ChannelKind; target: string }> = [];
    for (const rule of rules) {
        if (!evaluateNotificationRule(rule, payload)) continue;
        for (const ch of rule.channels) {
            const key = `${ch.channel}|${ch.target}`;
            if (seen.has(key)) continue;
            seen.add(key);
            out.push(ch);
        }
    }
    return out;
}

// ============================================================================
// Channel dispatcher
// ============================================================================

/** Reverse lookup table for routing a resolved (channel, target) pair to its adapter. */
type Adapter = (target: string, payload: NotificationPayload) => Promise<ChannelResult>;

export async function dispatchToChannels(
    targets: Array<{ channel: ChannelKind; target: string }>,
    payload: NotificationPayload,
    adapters: Partial<Record<ChannelKind, Adapter>>,
): Promise<Array<{ channel: ChannelKind; target: string; result: ChannelResult }>> {
    const results = await Promise.all(targets.map(async ({ channel, target }) => {
        const adapter = adapters[channel];
        if (!adapter) {
            log.warn('no adapter for channel', { channel });
            return { channel, target, result: { success: false, error: `no adapter registered for ${channel}` } };
        }
        const result = await adapter(target, payload);
        return { channel, target, result };
    }));
    return results;
}
