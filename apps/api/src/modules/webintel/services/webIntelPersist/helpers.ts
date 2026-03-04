/**
 * Web Intelligence Persistence — Helpers
 */

export function detectPlatform(url: string): string {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        if (hostname.includes('twitter.com') || hostname.includes('x.com')) return 'twitter';
        if (hostname.includes('reddit.com')) return 'reddit';
        if (hostname.includes('github.com')) return 'github';
        if (hostname.includes('linkedin.com')) return 'linkedin';
        if (hostname.includes('medium.com')) return 'blog';
        if (hostname.includes('wordpress.com') || hostname.includes('blogspot.com')) return 'blog';
        if (hostname.includes('pastebin.com')) return 'pastebin';
        if (hostname.includes('virustotal.com')) return 'virustotal';
        if (hostname.includes('shodan.io')) return 'shodan';
        return 'web';
    } catch {
        return 'unknown';
    }
}
