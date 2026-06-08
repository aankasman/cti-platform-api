/**
 * Notification rule DSL + channel routing tests.
 *
 * The HTTP adapters (Teams/Discord/PagerDuty) are network-dependent;
 * those get verified via the `/notifications/test/*` integration
 * endpoints. These unit tests lock the rule matcher + multi-rule
 * deduplication + the Zod schemas.
 */
import { describe, it, expect } from 'vitest';
import {
    evaluateNotificationRule,
    resolveRuleChannels,
    type NotificationRule,
} from '../services/notificationChannels';
import type { NotificationPayload } from '../services/notifications';
import { EvaluateRulesSchema, TestChannelWebhookSchema } from '../lib/schemas';

const critIocInKev: NotificationPayload = {
    type: 'ioc',
    severity: 'critical',
    title: 'CVE-2024-9999 exploit IOC seen',
    message: 'IP 1.2.3.4 observed targeting our /admin endpoint',
    data: { inKev: true, source: 'urlhaus' },
};

const mediumVuln: NotificationPayload = {
    type: 'vulnerability',
    severity: 'medium',
    title: 'CVE-2024-0001',
    message: '',
    data: { inKev: false },
};

describe('evaluateNotificationRule', () => {
    it('matches when every clause is satisfied', () => {
        const rule: NotificationRule = {
            name: 'critical-kev-pager',
            match: { severityIn: ['critical'], typeIn: ['ioc'], requireData: { inKev: true } },
            channels: [{ channel: 'pagerduty', target: 'PD_KEY' }],
        };
        expect(evaluateNotificationRule(rule, critIocInKev)).toBe(true);
    });

    it('rejects when severity does not match', () => {
        const rule: NotificationRule = {
            name: 'critical-only',
            match: { severityIn: ['critical'] },
            channels: [{ channel: 'slack', target: 'https://hooks/slack' }],
        };
        expect(evaluateNotificationRule(rule, mediumVuln)).toBe(false);
    });

    it('rejects when type does not match', () => {
        const rule: NotificationRule = {
            name: 'iocs-only',
            match: { typeIn: ['ioc'] },
            channels: [{ channel: 'slack', target: 'https://hooks/slack' }],
        };
        expect(evaluateNotificationRule(rule, mediumVuln)).toBe(false);
    });

    it('rejects when a requireData entry is missing or differs', () => {
        const rule: NotificationRule = {
            name: 'inkev-only',
            match: { requireData: { inKev: true } },
            channels: [{ channel: 'pagerduty', target: 'PD_KEY' }],
        };
        expect(evaluateNotificationRule(rule, mediumVuln)).toBe(false);          // inKev=false
        expect(evaluateNotificationRule(rule, { ...mediumVuln, data: {} })).toBe(false); // inKev absent
    });

    it('vacuously matches an empty match block', () => {
        const rule: NotificationRule = {
            name: 'route-everything',
            match: {},
            channels: [{ channel: 'slack', target: 'https://hooks/slack' }],
        };
        expect(evaluateNotificationRule(rule, mediumVuln)).toBe(true);
    });

    it('honours enabled=false', () => {
        const rule: NotificationRule = {
            name: 'disabled',
            enabled: false,
            match: {},
            channels: [{ channel: 'slack', target: 'x' }],
        };
        expect(evaluateNotificationRule(rule, critIocInKev)).toBe(false);
    });

    it('matches string + numeric requireData values', () => {
        const rule: NotificationRule = {
            name: 'string-num-match',
            match: { requireData: { source: 'urlhaus' } },
            channels: [{ channel: 'slack', target: 'x' }],
        };
        expect(evaluateNotificationRule(rule, critIocInKev)).toBe(true);
        expect(evaluateNotificationRule(rule, mediumVuln)).toBe(false);
    });
});

describe('resolveRuleChannels — dedup', () => {
    const r1: NotificationRule = {
        name: 'critical-pager',
        match: { severityIn: ['critical'] },
        channels: [{ channel: 'pagerduty', target: 'PD_KEY' }, { channel: 'slack', target: 'https://hooks/slack' }],
    };
    const r2: NotificationRule = {
        name: 'kev-pager',
        match: { requireData: { inKev: true } },
        channels: [{ channel: 'pagerduty', target: 'PD_KEY' }, { channel: 'teams', target: 'https://teams/webhook' }],
    };

    it('emits each (channel, target) only once even when two rules overlap', () => {
        const out = resolveRuleChannels([r1, r2], critIocInKev);
        const pairs = out.map(o => `${o.channel}|${o.target}`).sort();
        expect(pairs).toEqual([
            'pagerduty|PD_KEY',
            'slack|https://hooks/slack',
            'teams|https://teams/webhook',
        ]);
    });

    it('different targets on the same channel kind both fire', () => {
        const out = resolveRuleChannels([
            { name: 'a', match: {}, channels: [{ channel: 'slack', target: 'https://hooks/a' }] },
            { name: 'b', match: {}, channels: [{ channel: 'slack', target: 'https://hooks/b' }] },
        ], critIocInKev);
        expect(out).toHaveLength(2);
    });

    it('returns empty when no rule matches', () => {
        expect(resolveRuleChannels([r2], mediumVuln)).toEqual([]);
    });
});

describe('EvaluateRulesSchema', () => {
    it('accepts a typical rule+payload pair', () => {
        const r = EvaluateRulesSchema.parse({
            rules: [{
                name: 'critical-kev-pager',
                match: { severityIn: ['critical'], requireData: { inKev: true } },
                channels: [{ channel: 'pagerduty', target: 'PD_KEY' }],
            }],
            payload: { type: 'ioc', severity: 'critical', title: 't', message: 'm', data: { inKev: true } },
        });
        expect(r.rules).toHaveLength(1);
        expect(r.payload.severity).toBe('critical');
    });

    it('rejects an unknown channel kind', () => {
        expect(() => EvaluateRulesSchema.parse({
            rules: [{
                name: 'bad',
                match: {},
                channels: [{ channel: 'sms', target: '+15551234' }],
            }],
            payload: { type: 'ioc', severity: 'low', title: 't', message: 'm' },
        })).toThrow();
    });

    it('requires at least one channel per rule', () => {
        expect(() => EvaluateRulesSchema.parse({
            rules: [{ name: 'x', match: {}, channels: [] }],
            payload: { type: 'ioc', severity: 'low', title: 't', message: 'm' },
        })).toThrow();
    });
});

describe('TestChannelWebhookSchema', () => {
    it('accepts the PagerDuty routing-key shape (not a URL)', () => {
        // PD routing keys aren't URLs — schema is permissive on this so
        // the same shape works for Slack/Teams/Discord/PD.
        expect(TestChannelWebhookSchema.parse({ webhookUrl: 'R012345ABCDEFG' }).webhookUrl)
            .toBe('R012345ABCDEFG');
    });

    it('accepts a https:// webhook URL', () => {
        expect(TestChannelWebhookSchema.parse({ webhookUrl: 'https://outlook.office.com/webhook/abc' }).webhookUrl)
            .toBe('https://outlook.office.com/webhook/abc');
    });

    it('rejects empty', () => {
        expect(() => TestChannelWebhookSchema.parse({ webhookUrl: '' })).toThrow();
    });
});
