/**
 * Notification Service Tests
 *
 * Tests the pure logic functions: shouldNotify() and createAlertPayload().
 * No DB or network calls — these are self-contained unit tests.
 */

import { describe, it, expect } from 'vitest';
import { shouldNotify, createAlertPayload } from '../services/notifications';

// Helper to create a minimal NotificationConfig
function makeConfig(overrides: Record<string, any> = {}): any {
    return {
        id: 'test-id',
        userId: 'user-1',
        emailEnabled: true,
        emailAddress: 'test@example.com',
        slackEnabled: false,
        slackWebhookUrl: null,
        severityThreshold: 'medium',
        notifyOnNewIOC: true,
        notifyOnNewVuln: true,
        notifyOnThreatActor: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...overrides,
    };
}

describe('shouldNotify', () => {
    it('should allow notifications at or above severity threshold', () => {
        const config = makeConfig({ severityThreshold: 'medium' });

        expect(shouldNotify(config, { type: 'ioc', severity: 'critical', title: '', message: '' })).toBe(true);
        expect(shouldNotify(config, { type: 'ioc', severity: 'high', title: '', message: '' })).toBe(true);
        expect(shouldNotify(config, { type: 'ioc', severity: 'medium', title: '', message: '' })).toBe(true);
    });

    it('should block notifications below severity threshold', () => {
        const config = makeConfig({ severityThreshold: 'high' });

        expect(shouldNotify(config, { type: 'ioc', severity: 'medium', title: '', message: '' })).toBe(false);
        expect(shouldNotify(config, { type: 'ioc', severity: 'low', title: '', message: '' })).toBe(false);
    });

    it('should respect IOC notification preference', () => {
        const config = makeConfig({ notifyOnNewIOC: false });

        expect(shouldNotify(config, { type: 'ioc', severity: 'critical', title: '', message: '' })).toBe(false);
    });

    it('should respect vulnerability notification preference', () => {
        const config = makeConfig({ notifyOnNewVuln: false });

        expect(shouldNotify(config, { type: 'vulnerability', severity: 'critical', title: '', message: '' })).toBe(false);
    });

    it('should respect threat actor notification preference', () => {
        const config = makeConfig({ notifyOnThreatActor: false });

        expect(shouldNotify(config, { type: 'threat_actor', severity: 'critical', title: '', message: '' })).toBe(false);
    });

    it('should always notify on general alerts', () => {
        const config = makeConfig({ severityThreshold: 'critical' });

        expect(shouldNotify(config, { type: 'alert', severity: 'critical', title: '', message: '' })).toBe(true);
    });

    it('should reject unknown notification types', () => {
        const config = makeConfig();

        expect(shouldNotify(config, { type: 'unknown' as any, severity: 'critical', title: '', message: '' })).toBe(false);
    });
});

describe('createAlertPayload', () => {
    it('should create IOC alert payload', () => {
        const payload = createAlertPayload('ioc', 'critical', { value: '192.168.1.1' });

        expect(payload.type).toBe('ioc');
        expect(payload.severity).toBe('critical');
        expect(payload.title).toContain('critical');
        expect(payload.message).toContain('192.168.1.1');
    });

    it('should create vulnerability alert payload', () => {
        const payload = createAlertPayload('vulnerability', 'high', { cveId: 'CVE-2024-1234' });

        expect(payload.type).toBe('vulnerability');
        expect(payload.severity).toBe('high');
        expect(payload.message).toContain('CVE-2024-1234');
    });

    it('should create threat actor alert payload', () => {
        const payload = createAlertPayload('threat_actor', 'medium', { name: 'APT28' });

        expect(payload.type).toBe('threat_actor');
        expect(payload.message).toContain('APT28');
    });

    it('should handle missing details gracefully', () => {
        const payload = createAlertPayload('ioc', 'low', {});

        expect(payload.message).toContain('Unknown');
    });
});
