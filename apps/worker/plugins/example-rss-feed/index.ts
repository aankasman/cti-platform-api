/**
 * Example RSS Feed Plugin
 * 
 * Demonstrates how to create a custom feed worker plugin.
 * This plugin fetches and parses threat intelligence RSS feeds.
 */

import type { FeedPlugin, PluginContext } from '../../src/core/plugin-loader';

interface RSSItem {
    title: string;
    link: string;
    description: string;
    pubDate: string;
    category?: string[];
    guid: string;
}

interface ParsedThreatItem {
    id: string;
    title: string;
    url: string;
    description: string;
    publishedAt: Date;
    categories: string[];
    source: string;
}

// RSS feed URLs for threat intelligence
const FEED_URLS = [
    'https://www.cisa.gov/news.xml',
    'https://krebsonsecurity.com/feed/',
    'https://feeds.feedburner.com/TheHackersNews',
];

const plugin: FeedPlugin = {
    name: 'example-rss-feed',
    version: '1.0.0',

    async initialize(ctx: PluginContext): Promise<void> {
        ctx.logger.info('Initializing RSS Feed plugin');
    },

    async destroy(): Promise<void> {
        console.log('[RSS Feed] Plugin destroyed');
    },

    async fetch(ctx: PluginContext): Promise<RSSItem[]> {
        ctx.logger.info(`Fetching from ${FEED_URLS.length} RSS feeds...`);

        const allItems: RSSItem[] = [];

        for (const url of FEED_URLS) {
            try {
                const response = await fetch(url, {
                    headers: { 'Accept': 'application/rss+xml, application/xml, text/xml' }
                });

                if (!response.ok) {
                    ctx.logger.warn(`Failed to fetch ${url}: ${response.status}`);
                    continue;
                }

                const xml = await response.text();
                const items = parseRSS(xml);
                allItems.push(...items);

                ctx.logger.debug(`Fetched ${items.length} items from ${new URL(url).hostname}`);
            } catch (error) {
                ctx.logger.error(`Error fetching ${url}: ${error}`);
            }
        }

        ctx.logger.info(`Total items fetched: ${allItems.length}`);
        return allItems;
    },

    transform(data: RSSItem[]): ParsedThreatItem[] {
        return data.map(item => ({
            id: item.guid || item.link,
            title: item.title,
            url: item.link,
            description: item.description?.replace(/<[^>]*>/g, '') || '', // Strip HTML
            publishedAt: new Date(item.pubDate),
            categories: item.category || [],
            source: 'rss-feed',
        }));
    },

    validate(item: unknown): boolean {
        const threat = item as ParsedThreatItem;
        return !!(threat.id && threat.title && threat.url);
    },
};

// Simple RSS XML parser (in production, use a proper XML parser)
function parseRSS(xml: string): RSSItem[] {
    const items: RSSItem[] = [];

    // Extract items between <item> tags
    const itemMatches = xml.match(/<item>[\s\S]*?<\/item>/g) || [];

    for (const itemXml of itemMatches) {
        const title = extractTag(itemXml, 'title');
        const link = extractTag(itemXml, 'link');
        const description = extractTag(itemXml, 'description');
        const pubDate = extractTag(itemXml, 'pubDate');
        const guid = extractTag(itemXml, 'guid') || link;

        if (title && link) {
            items.push({
                title,
                link,
                description: description || '',
                pubDate: pubDate || new Date().toISOString(),
                guid: guid || link,
            });
        }
    }

    return items;
}

function extractTag(xml: string, tag: string): string | null {
    const regex = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
    const match = xml.match(regex);
    if (match) {
        return (match[1] || match[2] || '').trim();
    }
    return null;
}

export default plugin;
