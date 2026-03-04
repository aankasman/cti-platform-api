/**
 * Exa AI — Client Singleton & Webset Templates
 */

import Exa from 'exa-js';
import { createLogger } from '../../../../lib/logger';

const log = createLogger('Exa');

// =============================================================================
// Client Singleton
// =============================================================================

const EXA_API_KEY = process.env.EXA_API_KEY || '';

let _exa: InstanceType<typeof Exa> | null = null;

export function getExa(): InstanceType<typeof Exa> {
    if (!_exa) {
        if (!EXA_API_KEY) {
            throw new Error('[Exa] EXA_API_KEY is not set in environment');
        }
        _exa = new Exa(EXA_API_KEY);
    }
    return _exa;
}

// =============================================================================
// Webset Category Definitions
// =============================================================================

export type WebsetCategory = 'malware-c2' | 'zero-day-cve' | 'apt-actors' | 'socmint';

interface WebsetTemplate {
    title: string;
    search: {
        query: string;
        criteria: { description: string }[];
        count: number;
    };
    enrichments: {
        description: string;
        format: string;
        options?: { label: string }[];
    }[];
}

export const WEBSET_TEMPLATES: Record<WebsetCategory, WebsetTemplate> = {
    'malware-c2': {
        title: 'Rinjani: Malware & C2 Infrastructure',
        search: {
            query: 'Find social media posts, blog articles, and paste sites sharing IOCs for active malware campaigns, C2 servers, or botnet infrastructure',
            criteria: [
                { description: 'Contains specific technical indicators: IP addresses, domains, URLs, or file hashes' },
                { description: 'Discusses active or recently discovered malware, ransomware, or C2 infrastructure' },
                { description: 'Not a product advertisement or marketing content' },
            ],
            count: 100,
        },
        enrichments: [
            { description: 'Threat severity (critical/high/medium/low)', format: 'option' },
            { description: 'Malware family name if identifiable', format: 'text' },
            { description: 'List all IOC values found (IPs, domains, hashes) as comma-separated text', format: 'text' },
        ],
    },
    'zero-day-cve': {
        title: 'Rinjani: Zero-Day & CVE Disclosures',
        search: {
            query: 'Find posts and articles disclosing new zero-day vulnerabilities, CVE details, or proof-of-concept exploits',
            criteria: [
                { description: 'References a specific CVE ID or describes an unpatched vulnerability' },
                { description: 'Contains technical details: affected software, attack vector, or PoC code' },
                { description: 'From a credible source (researcher, security vendor, CERT)' },
            ],
            count: 50,
        },
        enrichments: [
            { description: 'CVE ID if available', format: 'text' },
            { description: 'Affected product/vendor', format: 'text' },
            { description: 'Exploit availability (PoC/weaponized/none)', format: 'option' },
        ],
    },
    'apt-actors': {
        title: 'Rinjani: APT & Threat Actor Intelligence',
        search: {
            query: 'Find threat intelligence reports, blog posts, and social media threads about APT groups, nation-state actors, or cybercriminal organizations',
            criteria: [
                { description: 'Names or attributes a specific threat actor or APT group' },
                { description: 'Includes TTPs, infrastructure, or campaign details' },
                { description: 'Not a generic cybersecurity news summary' },
            ],
            count: 50,
        },
        enrichments: [
            { description: 'Threat actor name/alias', format: 'text' },
            { description: 'Country/region of attribution', format: 'text' },
            { description: 'Primary motivation (espionage/financial/hacktivism/destruction)', format: 'option' },
        ],
    },
    'socmint': {
        title: 'Rinjani: Social Media Intelligence (SOCMINT)',
        search: {
            query: 'Find X/Twitter posts, Reddit threads, and forum discussions where security researchers share threat intelligence, IOCs, or vulnerability details',
            criteria: [
                { description: 'Posted by a cybersecurity professional, researcher, or threat intel analyst' },
                { description: 'Contains genuine technical intelligence (not retweets of news)' },
                { description: 'Includes actionable IOCs, MITRE ATT&CK references, or detailed analysis' },
            ],
            count: 100,
        },
        enrichments: [
            { description: 'Author type (researcher/vendor/analyst/anonymous)', format: 'option' },
            { description: 'Urgency level (critical/high/medium/informational)', format: 'option' },
            { description: 'Platform (Twitter/Reddit/Blog/Forum/Mastodon)', format: 'option' },
        ],
    },
};

/**
 * Get all available webset category templates.
 */
export function getWebsetCategories(): { id: WebsetCategory; title: string; description: string }[] {
    return Object.entries(WEBSET_TEMPLATES).map(([id, t]) => ({
        id: id as WebsetCategory,
        title: t.title,
        description: t.search.query,
    }));
}

/**
 * Health check: verify Exa API key is valid.
 */
export async function checkHealth() {
    try {
        const exa = getExa();
        const result = await exa.websets.list({ limit: 1 } as Record<string, unknown>);
        return { healthy: true, websets: (result as unknown as Record<string, unknown>)?.data ? ((result as unknown as Record<string, unknown[]>).data?.length ?? 0) : 0 };
    } catch (err: unknown) {
        return { healthy: false, error: (err as Error).message };
    }
}
