/**
 * Feed Registry Unit Tests
 *
 * Validates that the feed registry correctly maps source keys to handlers
 * and provides accurate lookup/enumeration functionality.
 */

import { describe, it, expect } from 'vitest';

describe('Feed Registry', () => {
    const EXPECTED_FEEDS = [
        'otx', 'cisa', 'nvd', 'abusessl', 'threatfox',
        'urlhaus', 'malwarebazaar', 'openphish', 'mitre', 'mispgalaxy',
    ];

    describe('getRegisteredFeeds', () => {
        it('should return all 10 registered feed source keys', async () => {
            const { getRegisteredFeeds } = await import('../services/feedSync/feedRegistry');

            const feeds = getRegisteredFeeds();

            expect(feeds).toHaveLength(10);
            for (const key of EXPECTED_FEEDS) {
                expect(feeds).toContain(key);
            }
        });

        it('should return stable key order (Object.keys)', async () => {
            const { getRegisteredFeeds } = await import('../services/feedSync/feedRegistry');

            const feeds1 = getRegisteredFeeds();
            const feeds2 = getRegisteredFeeds();

            expect(feeds1).toEqual(feeds2);
        });
    });

    describe('getFeedHandler', () => {
        it.each([
            'otx', 'cisa', 'nvd', 'abusessl', 'threatfox',
            'urlhaus', 'malwarebazaar', 'openphish', 'mitre', 'mispgalaxy',
        ])('should return a function handler for "%s"', async (source) => {
            const { getFeedHandler } = await import('../services/feedSync/feedRegistry');

            const handler = getFeedHandler(source);

            expect(handler).toBeDefined();
            expect(typeof handler).toBe('function');
        });

        it('should return undefined for unknown source keys', async () => {
            const { getFeedHandler } = await import('../services/feedSync/feedRegistry');

            expect(getFeedHandler('nonexistent')).toBeUndefined();
            expect(getFeedHandler('')).toBeUndefined();
            expect(getFeedHandler('virustotal')).toBeUndefined();
        });

        it('should not have a handler registered for "all" (handled by worker)', async () => {
            const { getFeedHandler } = await import('../services/feedSync/feedRegistry');

            expect(getFeedHandler('all')).toBeUndefined();
        });
    });

    describe('isFeedRegistered', () => {
        it.each([
            'otx', 'cisa', 'nvd', 'abusessl', 'threatfox',
            'urlhaus', 'malwarebazaar', 'openphish', 'mitre', 'mispgalaxy',
        ])('should return true for registered feed "%s"', async (source) => {
            const { isFeedRegistered } = await import('../services/feedSync/feedRegistry');

            expect(isFeedRegistered(source)).toBe(true);
        });

        it('should return false for unregistered sources', async () => {
            const { isFeedRegistered } = await import('../services/feedSync/feedRegistry');

            expect(isFeedRegistered('nonexistent')).toBe(false);
            expect(isFeedRegistered('all')).toBe(false);
            expect(isFeedRegistered('')).toBe(false);
        });
    });

    describe('consistency checks', () => {
        it('every key from getRegisteredFeeds should resolve via getFeedHandler', async () => {
            const { getRegisteredFeeds, getFeedHandler } = await import('../services/feedSync/feedRegistry');

            for (const key of getRegisteredFeeds()) {
                const handler = getFeedHandler(key);
                expect(handler, `No handler for registered feed '${key}'`).toBeDefined();
                expect(typeof handler).toBe('function');
            }
        });

        it('every key from getRegisteredFeeds should pass isFeedRegistered', async () => {
            const { getRegisteredFeeds, isFeedRegistered } = await import('../services/feedSync/feedRegistry');

            for (const key of getRegisteredFeeds()) {
                expect(isFeedRegistered(key), `isFeedRegistered('${key}') should be true`).toBe(true);
            }
        });
    });
});
