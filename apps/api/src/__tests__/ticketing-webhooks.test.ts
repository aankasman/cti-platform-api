/**
 * GitHub webhook handler tests — Phase 4 #6b.
 *
 * The HMAC verification + event-type gate are pure. The DB-touching
 * `applyGithubWebhook` path runs in the integration suite alongside
 * a real Postgres instance; here we exercise the contract that gates
 * everything else.
 */
import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { verifyGithubSignature, applyGithubWebhook } from '../services/ticketing/webhooks';

const SECRET = 'test-webhook-secret-shhh';
function sign(body: string, secret = SECRET): string {
    return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

describe('verifyGithubSignature', () => {
    it('accepts a valid signature', () => {
        const body = '{"action":"closed"}';
        expect(verifyGithubSignature(body, sign(body), SECRET)).toBe(true);
    });

    it('rejects a tampered body', () => {
        const body = '{"action":"closed"}';
        const sig = sign(body);
        expect(verifyGithubSignature('{"action":"opened"}', sig, SECRET)).toBe(false);
    });

    it('rejects a missing header', () => {
        expect(verifyGithubSignature('{}', undefined, SECRET)).toBe(false);
    });

    it('rejects a header without sha256= prefix', () => {
        // GitHub no longer sends sha1 but we still see legacy testers occasionally.
        expect(verifyGithubSignature('{}', 'sha1=deadbeef', SECRET)).toBe(false);
    });

    it('rejects a signature signed with the wrong secret', () => {
        const body = '{"action":"closed"}';
        expect(verifyGithubSignature(body, sign(body, 'wrong'), SECRET)).toBe(false);
    });

    it('rejects a malformed (truncated) signature without throwing', () => {
        // The Node crypto.timingSafeEqual throws on length mismatch; the guard catches it.
        expect(verifyGithubSignature('{}', 'sha256=abc', SECRET)).toBe(false);
    });
});

describe('applyGithubWebhook — event gating', () => {
    // These paths never touch the database (they return before the SELECT),
    // so they're safe to run in the unit suite even without a Postgres URL.

    it('ignores non-issues event types', async () => {
        const r = await applyGithubWebhook('push', { action: 'whatever' } as never);
        expect(r.kind).toBe('ignored');
    });

    it('ignores issues event with unhandled action and no state hint', async () => {
        const r = await applyGithubWebhook('issues', {
            action: 'labeled',
            issue: { number: 1, title: 't', state: 'open' },
            repository: { full_name: 'rinjanianalytics/cti-platform-api' },
        });
        expect(r.kind).toBe('ignored');
    });

    it('ignores issues event missing repository/full_name', async () => {
        const r = await applyGithubWebhook('issues', {
            action: 'closed',
            issue: { number: 1, title: 't', state: 'closed' },
        });
        expect(r.kind).toBe('ignored');
        expect((r as { reason: string }).reason).toMatch(/missing/);
    });

    it('ignores issues event missing issue.number', async () => {
        const r = await applyGithubWebhook('issues', {
            action: 'closed',
            issue: { title: 't', state: 'closed' },
            repository: { full_name: 'rinjanianalytics/cti-platform-api' },
        });
        expect(r.kind).toBe('ignored');
    });
});
