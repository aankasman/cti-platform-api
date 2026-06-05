/**
 * Auto-Enrichment Pipeline
 * 
 * Provides automated enrichment of IOCs with external threat intelligence sources.
 * Supports VirusTotal, AbuseIPDB, Shodan, and internal sources.
 */

import { createHash } from 'crypto';
import { promises as dns } from 'dns';

// ============================================================================
// Types
// ============================================================================

export type EnrichmentSource =
    | 'virustotal'
    | 'abuseipdb'
    | 'shodan'
    | 'zoomeye'
    | 'whois'
    | 'dns'
    | 'geoip'
    | 'ipinfo'
    | 'threatfox'
    | 'urlhaus'
    | 'safebrowsing'
    | 'mitre'
    | 'internal';

export type IOCType = 'ip' | 'domain' | 'url' | 'hash' | 'email';

export interface EnrichmentResult {
    source: EnrichmentSource;
    timestamp: Date;
    success: boolean;
    data?: Record<string, unknown>;
    error?: string;
    ttlSeconds: number;
}

export interface EnrichedIOC {
    value: string;
    type: IOCType;
    enrichments: EnrichmentResult[];
    overallScore?: number;
    riskLevel?: 'low' | 'medium' | 'high' | 'critical';
    scoreBreakdown?: Array<{ source: string; score: number; reason: string }>;
    lastEnrichedAt: Date;
    tags: string[];
}

export interface EnrichmentConfig {
    sources: EnrichmentSource[];
    priority?: 'speed' | 'comprehensive';
    forceRefresh?: boolean;
    timeout?: number;
}

// ============================================================================
// Enrichment Cache
// ============================================================================

interface CacheEntry {
    data: EnrichedIOC;
    expiresAt: Date;
}

const enrichmentCache = new Map<string, CacheEntry>();
const DEFAULT_TTL_SECONDS = 3600; // 1 hour

function getCacheKey(value: string, type: IOCType): string {
    return `${type}:${value.toLowerCase()}`;
}

function getCached(value: string, type: IOCType): EnrichedIOC | null {
    const key = getCacheKey(value, type);
    const entry = enrichmentCache.get(key);

    if (!entry) return null;
    if (entry.expiresAt < new Date()) {
        enrichmentCache.delete(key);
        return null;
    }

    return entry.data;
}

function setCache(data: EnrichedIOC, ttlSeconds: number = DEFAULT_TTL_SECONDS): void {
    const key = getCacheKey(data.value, data.type);
    enrichmentCache.set(key, {
        data,
        expiresAt: new Date(Date.now() + ttlSeconds * 1000),
    });
}

// ============================================================================
// IOC Type Detection
// ============================================================================

const IOC_PATTERNS = {
    ip: /^(\d{1,3}\.){3}\d{1,3}$/,
    ipv6: /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
    domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
    url: /^https?:\/\/.+/i,
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};

/**
 * Strip the trailing `:port` from `IPv4:port` or `domain:port` so the
 * type-detection regexes can match the bare host. ThreatFox emits its
 * C2-endpoint IOCs in this format natively (`198.44.177.179:80`,
 * `c2.example.com:443`), and the upstream lookup keys for VirusTotal
 * et al. don't include the port either — so we normalize on the way
 * in. IPv6 is excluded because its native form already contains
 * colons and `[ipv6]:port` bracketing isn't used by any of our
 * current feeds.
 *
 * Returns `{ host, port }` when a port was stripped, or `{ host: value }`
 * unchanged otherwise. The caller is responsible for using `host` for
 * upstream lookups and for surfacing `port` elsewhere if meaningful.
 */
export function splitHostPort(value: string): { host: string; port?: number } {
    const trimmed = value.trim();
    // IPv4:port — four octets then `:` then 1–5 digits, end of string.
    const ipv4Match = trimmed.match(/^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$/);
    if (ipv4Match) {
        const port = Number(ipv4Match[2]);
        if (port >= 0 && port <= 65535) return { host: ipv4Match[1], port };
    }
    // domain:port — same shape on the host side; domain regex inline
    // here rather than reusing IOC_PATTERNS.domain so we can anchor at
    // `:` instead of end-of-string.
    const domainMatch = trimmed.match(
        /^((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}):(\d{1,5})$/,
    );
    if (domainMatch) {
        const port = Number(domainMatch[2]);
        if (port >= 0 && port <= 65535) return { host: domainMatch[1], port };
    }
    return { host: trimmed };
}

export function detectIOCType(value: string): IOCType | null {
    // Normalize `IP:port` / `domain:port` to the bare host first — see
    // `splitHostPort()` for the rationale. ThreatFox C2 endpoints used
    // to fall through every pattern and noise the worker log with
    // "Unable to detect IOC type for value: 198.44.177.179:80" once
    // per affected child — that error is now resolved as `ip`.
    const trimmed = splitHostPort(value).host;

    if (IOC_PATTERNS.ip.test(trimmed) || IOC_PATTERNS.ipv6.test(trimmed)) return 'ip';
    if (IOC_PATTERNS.url.test(trimmed)) return 'url';
    if (IOC_PATTERNS.md5.test(trimmed) || IOC_PATTERNS.sha1.test(trimmed) || IOC_PATTERNS.sha256.test(trimmed)) return 'hash';
    if (IOC_PATTERNS.email.test(trimmed)) return 'email';
    if (IOC_PATTERNS.domain.test(trimmed)) return 'domain';

    return null;
}

// ============================================================================
// Individual Enrichment Sources
// ============================================================================

/**
 * VirusTotal enrichment (real API)
 */
async function enrichVirusTotal(value: string, type: IOCType): Promise<EnrichmentResult> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
        return {
            source: 'virustotal',
            timestamp: new Date(),
            success: false,
            error: 'VIRUSTOTAL_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        // Determine endpoint based on IOC type
        let endpoint: string;
        let lookupValue = value;

        switch (type) {
            case 'ip':
                endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
                break;
            case 'domain':
                endpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
                break;
            case 'url':
                // URLs need to be base64 encoded (without padding)
                const urlId = Buffer.from(value).toString('base64').replace(/=+$/, '');
                endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
                break;
            case 'hash':
                endpoint = `https://www.virustotal.com/api/v3/files/${value}`;
                break;
            default:
                return {
                    source: 'virustotal',
                    timestamp: new Date(),
                    success: false,
                    error: `Unsupported IOC type: ${type}`,
                    ttlSeconds: 86400,
                };
        }

        const response = await fetch(endpoint, {
            headers: {
                'x-apikey': apiKey,
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            if (response.status === 404) {
                return {
                    source: 'virustotal',
                    timestamp: new Date(),
                    success: true,
                    data: { found: false, message: 'Not found in VirusTotal' },
                    ttlSeconds: 3600,
                };
            }
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const data = await response.json() as {
            data?: {
                attributes?: {
                    last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
                    reputation?: number;
                    last_analysis_date?: number;
                    as_owner?: string;
                    country?: string;
                    registrar?: string;
                };
                id?: string;
            };
        };

        const stats = data.data?.attributes?.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);

        return {
            source: 'virustotal',
            timestamp: new Date(),
            success: true,
            data: {
                found: true,
                malicious,
                suspicious,
                harmless: stats.harmless || 0,
                undetected: stats.undetected || 0,
                total,
                reputation: data.data?.attributes?.reputation,
                lastAnalysisDate: data.data?.attributes?.last_analysis_date
                    ? new Date(data.data.attributes.last_analysis_date * 1000).toISOString()
                    : null,
                asOwner: data.data?.attributes?.as_owner,
                country: data.data?.attributes?.country,
                permalink: `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`,
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'virustotal',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * AbuseIPDB enrichment (real API)
 */
async function enrichAbuseIPDB(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'ip') {
        return {
            source: 'abuseipdb',
            timestamp: new Date(),
            success: false,
            error: 'AbuseIPDB only supports IP addresses',
            ttlSeconds: 86400,
        };
    }

    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
        return {
            source: 'abuseipdb',
            timestamp: new Date(),
            success: false,
            error: 'ABUSEIPDB_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`, {
            headers: {
                'Key': apiKey,
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            throw new Error(`AbuseIPDB API error: ${response.status}`);
        }

        const result = await response.json() as {
            data: {
                ipAddress: string;
                isPublic: boolean;
                ipVersion: number;
                isWhitelisted: boolean;
                abuseConfidenceScore: number;
                countryCode: string;
                usageType: string;
                isp: string;
                domain: string;
                hostnames: string[];
                totalReports: number;
                numDistinctUsers: number;
                lastReportedAt: string | null;
            };
        };

        const data = result.data;
        return {
            source: 'abuseipdb',
            timestamp: new Date(),
            success: true,
            data: {
                ipAddress: data.ipAddress,
                isPublic: data.isPublic,
                isWhitelisted: data.isWhitelisted,
                abuseConfidenceScore: data.abuseConfidenceScore,
                countryCode: data.countryCode,
                usageType: data.usageType,
                isp: data.isp,
                domain: data.domain,
                hostnames: data.hostnames,
                totalReports: data.totalReports,
                numDistinctUsers: data.numDistinctUsers,
                lastReportedAt: data.lastReportedAt,
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'abuseipdb',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * GeoIP enrichment (using IPInfo API)
 */
async function enrichGeoIP(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'ip') {
        return {
            source: 'geoip',
            timestamp: new Date(),
            success: false,
            error: 'GeoIP only supports IP addresses',
            ttlSeconds: 86400,
        };
    }

    // Use IPInfo API for GeoIP data
    const apiKey = process.env.IPINFO_API_KEY;
    if (!apiKey) {
        // Fallback to basic free lookup without API key
        try {
            const response = await fetch(`https://ipinfo.io/${value}/json`);
            if (!response.ok) throw new Error(`IPInfo error: ${response.status}`);

            const data = await response.json() as { city?: string; region?: string; country?: string; loc?: string; org?: string; timezone?: string };
            const [lat, lon] = (data.loc || '0,0').split(',').map(Number);

            return {
                source: 'geoip',
                timestamp: new Date(),
                success: true,
                data: {
                    city: data.city,
                    region: data.region,
                    country: data.country,
                    countryCode: data.country,
                    latitude: lat,
                    longitude: lon,
                    timezone: data.timezone,
                    org: data.org,
                    asn: data.org?.split(' ')[0],
                },
                ttlSeconds: 86400,
            };
        } catch {
            return {
                source: 'geoip',
                timestamp: new Date(),
                success: false,
                error: 'GeoIP lookup failed',
                ttlSeconds: 3600,
            };
        }
    }

    try {
        const response = await fetch(`https://ipinfo.io/${value}?token=${apiKey}`);
        if (!response.ok) throw new Error(`IPInfo API error: ${response.status}`);

        const data = await response.json() as {
            ip?: string; hostname?: string; city?: string; region?: string;
            country?: string; loc?: string; org?: string; postal?: string; timezone?: string;
        };
        const [lat, lon] = (data.loc || '0,0').split(',').map(Number);

        return {
            source: 'geoip',
            timestamp: new Date(),
            success: true,
            data: {
                ip: data.ip,
                hostname: data.hostname,
                city: data.city,
                region: data.region,
                country: data.country,
                countryCode: data.country,
                latitude: lat,
                longitude: lon,
                org: data.org,
                asn: data.org?.split(' ')[0],
                postal: data.postal,
                timezone: data.timezone,
            },
            ttlSeconds: 86400,
        };
    } catch (err: any) {
        return {
            source: 'geoip',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * IPInfo enrichment (real API)
 */
async function enrichIPInfo(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'ip') {
        return {
            source: 'ipinfo',
            timestamp: new Date(),
            success: false,
            error: 'IPInfo only supports IP addresses',
            ttlSeconds: 86400,
        };
    }

    const apiKey = process.env.IPINFO_API_KEY;
    if (!apiKey) {
        return {
            source: 'ipinfo',
            timestamp: new Date(),
            success: false,
            error: 'IPINFO_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        const response = await fetch(`https://ipinfo.io/${value}?token=${apiKey}`);

        if (!response.ok) {
            throw new Error(`IPInfo API error: ${response.status}`);
        }

        const data = await response.json() as {
            ip?: string;
            hostname?: string;
            city?: string;
            region?: string;
            country?: string;
            loc?: string;
            org?: string;
            postal?: string;
            timezone?: string;
        };
        const [lat, lon] = (data.loc || '0,0').split(',').map(Number);

        return {
            source: 'ipinfo',
            timestamp: new Date(),
            success: true,
            data: {
                ip: data.ip,
                hostname: data.hostname,
                city: data.city,
                region: data.region,
                country: data.country,
                countryCode: data.country,
                latitude: lat,
                longitude: lon,
                org: data.org,
                asn: data.org?.split(' ')[0],
                postal: data.postal,
                timezone: data.timezone,
            },
            ttlSeconds: 86400,
        };
    } catch (err: any) {
        return {
            source: 'ipinfo',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * WHOIS enrichment (using RiskIQ PassiveTotal)
 */
async function enrichWHOIS(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'domain' && type !== 'ip') {
        return {
            source: 'whois',
            timestamp: new Date(),
            success: false,
            error: 'WHOIS only supports domains and IPs',
            ttlSeconds: 86400,
        };
    }

    const apiUser = process.env.RISKIQ_USER;
    const apiKey = process.env.RISKIQ_API_KEY;

    if (!apiUser || !apiKey) {
        // Return basic response without API
        return {
            source: 'whois',
            timestamp: new Date(),
            success: false,
            error: 'RISKIQ_USER and RISKIQ_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        const endpoint = type === 'domain'
            ? `https://api.riskiq.net/pt/v2/whois?query=${value}`
            : `https://api.riskiq.net/pt/v2/whois?query=${value}`;

        const auth = Buffer.from(`${apiUser}:${apiKey}`).toString('base64');

        const response = await fetch(endpoint, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            throw new Error(`RiskIQ API error: ${response.status}`);
        }

        const data = await response.json() as {
            registrar?: string;
            registryUpdatedAt?: string;
            expiresAt?: string;
            registeredAt?: string;
            nameServers?: string[];
            organization?: string;
            registrant?: { country?: string; organization?: string };
            admin?: { email?: string };
        };

        return {
            source: 'whois',
            timestamp: new Date(),
            success: true,
            data: {
                registrar: data.registrar,
                createdDate: data.registeredAt,
                expiresDate: data.expiresAt,
                updatedDate: data.registryUpdatedAt,
                nameServers: data.nameServers,
                registrantOrg: data.registrant?.organization || data.organization,
                registrantCountry: data.registrant?.country,
                adminEmail: data.admin?.email,
            },
            ttlSeconds: 43200,
        };
    } catch (err: any) {
        return {
            source: 'whois',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

// ============================================================================
// Enrichment Engine
// ============================================================================

/**
 * DNS enrichment (native Node.js resolution)
 */
async function enrichDNS(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'domain') {
        return {
            source: 'dns',
            timestamp: new Date(),
            success: false,
            error: 'DNS enrichment only supports domains',
            ttlSeconds: 86400,
        };
    }

    try {
        const [aRecords, aaaaRecords, mxRecords, txtRecords, nsRecords] = await Promise.allSettled([
            dns.resolve4(value),
            dns.resolve6(value),
            dns.resolveMx(value),
            dns.resolveTxt(value),
            dns.resolveNs(value),
        ]);

        return {
            source: 'dns',
            timestamp: new Date(),
            success: true,
            data: {
                aRecords: aRecords.status === 'fulfilled' ? aRecords.value : [],
                aaaaRecords: aaaaRecords.status === 'fulfilled' ? aaaaRecords.value : [],
                mxRecords: mxRecords.status === 'fulfilled' ? mxRecords.value : [],
                txtRecords: txtRecords.status === 'fulfilled' ? txtRecords.value.flat() : [],
                nsRecords: nsRecords.status === 'fulfilled' ? nsRecords.value : [],
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'dns',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * ThreatFox enrichment (Abuse.ch)
 * Supports: IP, domain, URL, hash
 */
async function enrichThreatFox(value: string, type: IOCType): Promise<EnrichmentResult> {
    const apiKey = process.env.ABUSECH_API_KEY || process.env.THREATFOX_AUTH_KEY;

    if (!apiKey) {
        return {
            source: 'threatfox',
            timestamp: new Date(),
            success: false,
            error: 'ABUSECH_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Auth-Key': apiKey,
            },
            body: JSON.stringify({
                query: 'search_ioc',
                search_term: value,
            }),
        });

        if (!response.ok) {
            throw new Error(`ThreatFox API error: ${response.status}`);
        }

        const data = await response.json() as {
            query_status: string;
            data?: Array<{
                id: string;
                ioc: string;
                threat_type: string;
                malware: string;
                malware_printable: string;
                confidence_level: number;
                first_seen: string;
                last_seen: string;
                tags: string[];
            }>;
        };

        if (data.query_status === 'no_result') {
            return {
                source: 'threatfox',
                timestamp: new Date(),
                success: true,
                data: { found: false, message: 'Not found in ThreatFox' },
                ttlSeconds: 3600,
            };
        }

        const results = Array.isArray(data.data) ? data.data : [];
        return {
            source: 'threatfox',
            timestamp: new Date(),
            success: true,
            data: {
                found: true,
                matchCount: results.length,
                matches: results.slice(0, 5).map(r => ({
                    threatType: r.threat_type,
                    malware: r.malware_printable,
                    confidence: r.confidence_level,
                    firstSeen: r.first_seen,
                    lastSeen: r.last_seen,
                    tags: r.tags,
                })),
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'threatfox',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * URLhaus enrichment (Abuse.ch)
 * Supports: URL, domain, hash
 */
async function enrichURLhaus(value: string, type: IOCType): Promise<EnrichmentResult> {
    try {
        let endpoint: string;
        let body: string;

        // Auth-Key required since 2025 — register at https://auth.abuse.ch
        // Same auth portal as ThreatFox — use ABUSECH_API_KEY
        const authKey = process.env.ABUSECH_API_KEY || process.env.URLHAUS_API_KEY || process.env.THREATFOX_AUTH_KEY;
        if (!authKey) {
            return {
                source: 'urlhaus',
                timestamp: new Date(),
                success: false,
                error: 'ABUSECH_API_KEY not configured (register at https://auth.abuse.ch)',
                ttlSeconds: 86400,
            };
        }

        switch (type) {
            case 'url':
                endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
                body = `url=${encodeURIComponent(value)}`;
                break;
            case 'domain':
                endpoint = 'https://urlhaus-api.abuse.ch/v1/host/';
                body = `host=${encodeURIComponent(value)}`;
                break;
            case 'hash':
                endpoint = value.length === 32
                    ? 'https://urlhaus-api.abuse.ch/v1/payload/'
                    : 'https://urlhaus-api.abuse.ch/v1/payload/';
                body = value.length === 32
                    ? `md5_hash=${value}`
                    : `sha256_hash=${value}`;
                break;
            default:
                return {
                    source: 'urlhaus',
                    timestamp: new Date(),
                    success: false,
                    error: `URLhaus does not support ${type}`,
                    ttlSeconds: 86400,
                };
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Auth-Key': authKey,
            },
            body,
        });

        if (!response.ok) {
            throw new Error(`URLhaus API error: ${response.status}`);
        }

        const data = await response.json() as {
            query_status: string;
            url_count?: number;
            urls?: Array<{ url: string; url_status: string; threat: string; date_added: string }>;
            threat?: string;
            blacklists?: { spamhaus_dbl?: string; surbl?: string };
        };

        if (data.query_status === 'no_results') {
            return {
                source: 'urlhaus',
                timestamp: new Date(),
                success: true,
                data: { found: false, message: 'Not found in URLhaus' },
                ttlSeconds: 3600,
            };
        }

        return {
            source: 'urlhaus',
            timestamp: new Date(),
            success: true,
            data: {
                found: true,
                urlCount: data.url_count,
                threat: data.threat,
                blacklists: data.blacklists,
                urls: data.urls?.slice(0, 5).map(u => ({
                    url: u.url,
                    status: u.url_status,
                    threat: u.threat,
                    dateAdded: u.date_added,
                })),
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'urlhaus',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * Shodan enrichment (real API)
 * Supports: IP addresses — returns open ports, services, vulns, OS, org/ISP
 */
async function enrichShodan(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'ip') {
        return {
            source: 'shodan',
            timestamp: new Date(),
            success: false,
            error: 'Shodan only supports IP addresses',
            ttlSeconds: 86400,
        };
    }

    const apiKey = process.env.SHODAN_API_KEY;
    if (!apiKey) {
        // Free fallback — Shodan's InternetDB endpoint (no key required)
        // returns a slimmer payload than the paid `/shodan/host/:ip` endpoint
        // but covers the highest-signal fields: open ports, hostnames, tags,
        // and known CVEs. Lets the platform surface SOMETHING useful for
        // every IP IOC even when the operator hasn't registered for a key.
        // Same `source: 'shodan'` envelope so the dashboard's Shodan section
        // renders either payload uniformly.
        try {
            const r = await fetch(`https://internetdb.shodan.io/${value}`);
            if (r.status === 404) {
                return {
                    source: 'shodan',
                    timestamp: new Date(),
                    success: true,
                    data: { found: false, message: 'No Shodan data for this IP', via: 'internetdb' },
                    ttlSeconds: 3600,
                };
            }
            if (!r.ok) throw new Error(`InternetDB ${r.status}`);
            const idb = await r.json() as {
                ip?: string;
                ports?: number[];
                cpes?: string[];
                hostnames?: string[];
                tags?: string[];
                vulns?: string[];
            };
            return {
                source: 'shodan',
                timestamp: new Date(),
                success: true,
                data: {
                    found: true,
                    via: 'internetdb',
                    ip: idb.ip || value,
                    ports: idb.ports || [],
                    portCount: (idb.ports || []).length,
                    vulns: idb.vulns || [],
                    vulnCount: (idb.vulns || []).length,
                    hostnames: idb.hostnames || [],
                    tags: idb.tags || [],
                    cpes: idb.cpes || [],
                },
                // InternetDB refreshes daily — match TTL to that cadence
                // rather than the paid API's hourly so we don't beat on it.
                ttlSeconds: 86400,
            };
        } catch (err: any) {
            return {
                source: 'shodan',
                timestamp: new Date(),
                success: false,
                error: `InternetDB fallback failed: ${err.message}`,
                ttlSeconds: 3600,
            };
        }
    }

    try {
        const response = await fetch(`https://api.shodan.io/shodan/host/${value}?key=${apiKey}`);

        if (response.status === 404) {
            return {
                source: 'shodan',
                timestamp: new Date(),
                success: true,
                data: { found: false, message: 'No Shodan data for this IP' },
                ttlSeconds: 3600,
            };
        }

        if (!response.ok) {
            throw new Error(`Shodan API error: ${response.status}`);
        }

        const data = await response.json() as {
            ip_str?: string;
            ports?: number[];
            vulns?: string[];
            os?: string;
            org?: string;
            isp?: string;
            country_code?: string;
            country_name?: string;
            city?: string;
            hostnames?: string[];
            domains?: string[];
            last_update?: string;
            data?: Array<{
                port: number;
                transport: string;
                product?: string;
                version?: string;
                cpe?: string[];
            }>;
        };

        // Extract service banners (top 10)
        const services = (data.data || []).slice(0, 10).map(svc => ({
            port: svc.port,
            transport: svc.transport,
            product: svc.product || null,
            version: svc.version || null,
        }));

        return {
            source: 'shodan',
            timestamp: new Date(),
            success: true,
            data: {
                found: true,
                via: 'paid-api',
                ip: data.ip_str,
                ports: data.ports || [],
                portCount: (data.ports || []).length,
                vulns: data.vulns || [],
                vulnCount: (data.vulns || []).length,
                os: data.os || null,
                org: data.org || null,
                isp: data.isp || null,
                countryCode: data.country_code || null,
                country: data.country_name || null,
                city: data.city || null,
                hostnames: data.hostnames || [],
                domains: data.domains || [],
                services,
                lastUpdate: data.last_update || null,
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'shodan',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * ZoomEye enrichment (alternative to Shodan)
 * Uses ZoomEye API v2: POST /v2/search with qbase64 in JSON body
 * Supports: IP addresses — returns open ports, services, OS, geo
 */
async function enrichZoomEye(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'ip') {
        return {
            source: 'zoomeye',
            timestamp: new Date(),
            success: false,
            error: 'ZoomEye only supports IP addresses',
            ttlSeconds: 86400,
        };
    }

    const apiKey = process.env.ZOOMEYE_API_KEY;
    if (!apiKey) {
        return {
            source: 'zoomeye',
            timestamp: new Date(),
            success: false,
            error: 'ZOOMEYE_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        // ZoomEye API v2 uses POST with base64-encoded query in JSON body
        const qbase64 = Buffer.from(`ip="${value}"`).toString('base64');
        const response = await fetch('https://api.zoomeye.ai/v2/search', {
            method: 'POST',
            headers: {
                'API-KEY': apiKey,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                qbase64,
                page: 1,
                pagesize: 20,
            }),
        });

        if (response.status === 403) {
            throw new Error('ZoomEye API: access denied (check API key or plan)');
        }

        if (!response.ok) {
            throw new Error(`ZoomEye API error: ${response.status}`);
        }

        const result = await response.json() as {
            code?: number;
            message?: string;
            total?: number;
            data?: Array<{
                ip?: string;
                port?: number;
                service?: string;
                product?: string;
                version?: string;
                os?: string;
                hostname?: string;
                device?: string;
                banner?: string;
                'country.name'?: string;
                'city.name'?: string;
                'isp.name'?: string;
                'organization.name'?: string;
                'continent.name'?: string;
                'province.name'?: string;
                update_time?: string;
                protocol?: string;
            }>;
        };

        // Check ZoomEye response code (60000 = success)
        if (result.code && result.code !== 60000) {
            throw new Error(`ZoomEye API: ${result.message || `error code ${result.code}`}`);
        }

        const matches = Array.isArray(result.data) ? result.data : [];
        if (matches.length === 0) {
            return {
                source: 'zoomeye',
                timestamp: new Date(),
                success: true,
                data: { found: false, message: 'No ZoomEye data for this IP' },
                ttlSeconds: 3600,
            };
        }

        // Extract unique ports and services from matches
        const ports = [...new Set(matches.map(m => m.port).filter(Boolean))] as number[];
        const services = matches
            .filter(m => m.port)
            .map(m => ({
                port: m.port!,
                protocol: m.protocol || 'tcp',
                service: m.service || 'unknown',
                product: m.product || null,
                version: m.version || null,
            }));

        // Get geo and OS from first match
        const first = matches[0];
        const os = matches.find(m => m.os)?.os || null;

        return {
            source: 'zoomeye',
            timestamp: new Date(),
            success: true,
            data: {
                found: true,
                ip: value,
                total: result.total || matches.length,
                ports,
                portCount: ports.length,
                os,
                hostname: first?.hostname || null,
                device: first?.device || null,
                country: first?.['country.name'] || null,
                city: first?.['city.name'] || null,
                province: first?.['province.name'] || null,
                continent: first?.['continent.name'] || null,
                org: first?.['organization.name'] || null,
                isp: first?.['isp.name'] || null,
                services: services.slice(0, 10),
                lastSeen: first?.update_time || null,
            },
            ttlSeconds: 3600,
        };
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'ZoomEye lookup failed';
        return {
            source: 'zoomeye',
            timestamp: new Date(),
            success: false,
            error: message,
            ttlSeconds: 3600,
        };
    }
}

const ENRICHMENT_FUNCTIONS: Record<EnrichmentSource, (value: string, type: IOCType) => Promise<EnrichmentResult>> = {
    virustotal: enrichVirusTotal,
    abuseipdb: enrichAbuseIPDB,
    geoip: enrichGeoIP,
    ipinfo: enrichIPInfo,
    whois: enrichWHOIS,
    dns: enrichDNS,
    threatfox: enrichThreatFox,
    urlhaus: enrichURLhaus,
    safebrowsing: enrichSafeBrowsing,
    shodan: enrichShodan,
    zoomeye: enrichZoomEye,
    mitre: async () => ({ source: 'mitre', timestamp: new Date(), success: false, error: 'Not implemented', ttlSeconds: 86400 }),
    internal: async () => ({ source: 'internal', timestamp: new Date(), success: false, error: 'Not implemented', ttlSeconds: 86400 }),
};

/**
 * Google Safe Browsing enrichment
 * Supports: URL, domain
 */
async function enrichSafeBrowsing(value: string, type: IOCType): Promise<EnrichmentResult> {
    if (type !== 'url' && type !== 'domain') {
        return {
            source: 'safebrowsing',
            timestamp: new Date(),
            success: false,
            error: 'Safe Browsing only supports URLs and domains',
            ttlSeconds: 86400,
        };
    }

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey) {
        return {
            source: 'safebrowsing',
            timestamp: new Date(),
            success: false,
            error: 'GOOGLE_SAFE_BROWSING_API_KEY not configured',
            ttlSeconds: 86400,
        };
    }

    try {
        // For domains, wrap in URL format
        const urlToCheck = type === 'domain' ? `http://${value}/` : value;

        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client: {
                    clientId: 'rinjani-cti',
                    clientVersion: '1.0.0',
                },
                threatInfo: {
                    threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    platformTypes: ['ANY_PLATFORM'],
                    threatEntryTypes: ['URL'],
                    threatEntries: [{ url: urlToCheck }],
                },
            }),
        });

        if (!response.ok) {
            throw new Error(`Safe Browsing API error: ${response.status}`);
        }

        const data = await response.json() as {
            matches?: Array<{
                threatType: string;
                platformType: string;
                threat: { url: string };
                cacheDuration: string;
                threatEntryType: string;
            }>;
        };

        const matches = data.matches || [];
        const isThreat = matches.length > 0;

        return {
            source: 'safebrowsing',
            timestamp: new Date(),
            success: true,
            data: {
                isThreat,
                threatCount: matches.length,
                threats: matches.map(m => ({
                    type: m.threatType,
                    platform: m.platformType,
                    url: m.threat.url,
                })),
                message: isThreat
                    ? `Found ${matches.length} threat(s): ${matches.map(m => m.threatType).join(', ')}`
                    : 'No threats detected',
            },
            ttlSeconds: 3600,
        };
    } catch (err: any) {
        return {
            source: 'safebrowsing',
            timestamp: new Date(),
            success: false,
            error: err.message,
            ttlSeconds: 3600,
        };
    }
}

/**
 * Calculate overall risk score from enrichment results
 */
function calculateRiskScore(enrichments: EnrichmentResult[]): { score: number; level: 'low' | 'medium' | 'high' | 'critical'; breakdown: Array<{ source: string; score: number; reason: string }> } {
    let totalScore = 0;
    let scoreCount = 0;
    const breakdown: Array<{ source: string; score: number; reason: string }> = [];

    for (const result of enrichments) {
        if (!result.success) continue;

        switch (result.source) {
            case 'virustotal': {
                const malicious = (result.data?.malicious as number) || 0;
                const suspicious = (result.data?.suspicious as number) || 0;
                const total = (result.data?.total as number) || 93;
                if (malicious > 0 || suspicious > 0) {
                    // Score based on absolute detection count, not ratio.
                    // VT has ~70-93 engines; even known-malicious domains rarely exceed 30% detection.
                    // Thresholds aligned with VT community interpretation:
                    //   1 detection  → 25  (notable)
                    //   3 detections → 40  (suspicious)
                    //   5 detections → 60  (likely malicious)
                    //  10 detections → 80  (confirmed malicious)
                    //  20+ detections → 95+ (widely known threat)
                    let vtScore: number;
                    if (malicious >= 20) vtScore = 95;
                    else if (malicious >= 10) vtScore = 80 + Math.min(15, (malicious - 10) * 1.5);
                    else if (malicious >= 5) vtScore = 60 + (malicious - 5) * 4;
                    else if (malicious >= 3) vtScore = 40 + (malicious - 3) * 10;
                    else if (malicious >= 1) vtScore = 25 + (malicious - 1) * 7.5;
                    else vtScore = 0;
                    // Suspicious detections add a bonus
                    vtScore = Math.min(100, vtScore + suspicious * 3);
                    const rounded = Math.round(vtScore);
                    totalScore += rounded;
                    scoreCount++;
                    breakdown.push({
                        source: 'VirusTotal',
                        score: rounded,
                        reason: `${malicious}/${total} engines flagged as malicious${suspicious > 0 ? `, ${suspicious} suspicious` : ''}`,
                    });
                } else {
                    breakdown.push({ source: 'VirusTotal', score: 0, reason: `0/${total} engines — clean` });
                }
                break;
            }
            case 'abuseipdb': {
                const confidence = result.data?.abuseConfidenceScore as number;
                if (confidence) {
                    totalScore += confidence;
                    scoreCount++;
                    const reports = (result.data?.totalReports as number) || 0;
                    breakdown.push({
                        source: 'AbuseIPDB',
                        score: confidence,
                        reason: `${confidence}% abuse confidence, ${reports} report${reports !== 1 ? 's' : ''}`,
                    });
                } else {
                    breakdown.push({ source: 'AbuseIPDB', score: 0, reason: '0% abuse confidence — clean' });
                }
                break;
            }
            case 'shodan': {
                if (result.data?.found === false) break;
                const ports = (result.data?.ports as number[]) || [];
                const vulns = (result.data?.vulns as string[]) || [];
                // Dangerous ports: RDP(3389), SMB(445), Telnet(23), FTP(21), MySQL(3306), MSSQL(1433), Redis(6379), Mongo(27017)
                const dangerousPorts = [3389, 445, 23, 21, 3306, 1433, 6379, 27017];
                const exposedDangerous = ports.filter(p => dangerousPorts.includes(p)).length;
                let shodanScore = Math.min(100, exposedDangerous * 20 + vulns.length * 10 + (ports.length > 10 ? 15 : 0));
                if (shodanScore > 0) {
                    totalScore += shodanScore;
                    scoreCount++;
                }
                const reasons: string[] = [];
                if (ports.length > 0) reasons.push(`${ports.length} open port${ports.length !== 1 ? 's' : ''}`);
                if (exposedDangerous > 0) reasons.push(`${exposedDangerous} high-risk`);
                if (vulns.length > 0) reasons.push(`${vulns.length} CVE${vulns.length !== 1 ? 's' : ''}`);
                breakdown.push({
                    source: 'Shodan',
                    score: shodanScore,
                    reason: reasons.length > 0 ? reasons.join(', ') : 'No significant exposure',
                });
                break;
            }
            case 'zoomeye': {
                if (result.data?.found === false) break;
                const zPorts = (result.data?.ports as number[]) || [];
                const dangerousPorts = [3389, 445, 23, 21, 3306, 1433, 6379, 27017];
                const zExposed = zPorts.filter(p => dangerousPorts.includes(p)).length;
                let zScore = Math.min(100, zExposed * 20 + (zPorts.length > 10 ? 15 : 0));
                if (zScore > 0) {
                    totalScore += zScore;
                    scoreCount++;
                }
                const zReasons: string[] = [];
                if (zPorts.length > 0) zReasons.push(`${zPorts.length} open port${zPorts.length !== 1 ? 's' : ''}`);
                if (zExposed > 0) zReasons.push(`${zExposed} high-risk`);
                breakdown.push({
                    source: 'ZoomEye',
                    score: zScore,
                    reason: zReasons.length > 0 ? zReasons.join(', ') : 'No significant exposure',
                });
                break;
            }
            case 'threatfox': {
                const tfFound = result.data?.found;
                const tfMatches = (result.data?.matches as Array<Record<string, unknown>>) || [];
                if (tfFound && tfMatches.length > 0) {
                    const tfScore = Math.min(100, 50 + tfMatches.length * 10);
                    totalScore += tfScore;
                    scoreCount++;
                    breakdown.push({
                        source: 'ThreatFox',
                        score: tfScore,
                        reason: `${tfMatches.length} IOC match${tfMatches.length !== 1 ? 'es' : ''} found`,
                    });
                }
                break;
            }
        }
    }

    const avgScore = scoreCount > 0 ? totalScore / scoreCount : 0;

    let level: 'low' | 'medium' | 'high' | 'critical';
    if (avgScore >= 80) level = 'critical';
    else if (avgScore >= 50) level = 'high';
    else if (avgScore >= 20) level = 'medium';
    else level = 'low';

    return { score: Math.round(avgScore), level, breakdown };
}

/**
 * Generate tags based on enrichment data
 */
function generateTags(enrichments: EnrichmentResult[]): string[] {
    const tags: Set<string> = new Set();

    for (const result of enrichments) {
        if (!result.success) continue;

        switch (result.source) {
            case 'abuseipdb':
                if ((result.data?.abuseConfidenceScore as number) > 50) {
                    tags.add('reported-abuse');
                }
                if (result.data?.countryCode) {
                    tags.add(`country:${result.data.countryCode}`);
                }
                break;
            case 'virustotal': {
                const vtMalicious = (result.data?.malicious as number) || 0;
                if (vtMalicious > 0) {
                    tags.add('malicious-detection');
                }
                if (vtMalicious >= 10) {
                    tags.add('high-detection');
                }
                break;
            }
            case 'geoip':
                if (result.data?.countryCode) {
                    tags.add(`geo:${result.data.countryCode}`);
                }
                if (result.data?.asn) {
                    tags.add(result.data.asn as string);
                }
                break;
            case 'shodan': {
                if (result.data?.found === false) break;
                const shodanPorts = (result.data?.ports as number[]) || [];
                const shodanVulns = (result.data?.vulns as string[]) || [];
                if (shodanPorts.includes(3389)) tags.add('shodan:open-rdp');
                if (shodanPorts.includes(445)) tags.add('shodan:open-smb');
                if (shodanPorts.includes(23)) tags.add('shodan:open-telnet');
                if (shodanPorts.includes(21)) tags.add('shodan:open-ftp');
                if (shodanPorts.includes(6379)) tags.add('shodan:open-redis');
                if (shodanPorts.includes(27017)) tags.add('shodan:open-mongo');
                if (shodanVulns.length > 0) tags.add('shodan:has-vulns');
                if (shodanPorts.length > 10) tags.add('shodan:high-exposure');
                if (result.data?.org) tags.add(`org:${result.data.org}`);
                break;
            }
        }
    }

    return Array.from(tags);
}

/**
 * Enrich a single IOC
 */
export async function enrichIOC(
    value: string,
    config: EnrichmentConfig = { sources: ['virustotal', 'geoip'] }
): Promise<EnrichedIOC> {
    // Normalize `IP:port` / `domain:port` to the bare host before any
    // upstream lookup — VirusTotal's /ip_addresses/ and /domains/
    // endpoints don't accept ports, so feeding them the raw ThreatFox
    // value would 404 every C2 endpoint silently. We keep the
    // original `value` for the cache key + returned record so
    // callers don't need to know about the rewrite.
    const { host: lookupValue } = splitHostPort(value);
    const type = detectIOCType(value);
    if (!type) {
        throw new Error(`Unable to detect IOC type for value: ${value}`);
    }

    // Check cache first
    if (!config.forceRefresh) {
        const cached = getCached(value, type);
        if (cached) return cached;
    }

    // Run enrichments in parallel — pass the port-stripped `lookupValue`
    // so VT/GeoIP/etc. see a clean host. The cache key + returned
    // `EnrichedIOC.value` below keep the caller's original input so
    // the IOC drawer still shows "198.44.177.179:80" with port context.
    const enrichmentPromises = config.sources.map(source => {
        const fn = ENRICHMENT_FUNCTIONS[source];
        return fn ? fn(lookupValue, type) : Promise.resolve({
            source,
            timestamp: new Date(),
            success: false,
            error: 'Unknown source',
            ttlSeconds: 86400,
        });
    });

    const enrichments = await Promise.all(enrichmentPromises);
    const { score, level, breakdown } = calculateRiskScore(enrichments);
    const tags = generateTags(enrichments);

    const result: EnrichedIOC = {
        value,
        type,
        enrichments,
        overallScore: score,
        riskLevel: level,
        scoreBreakdown: breakdown,
        lastEnrichedAt: new Date(),
        tags,
    };

    // Cache the result
    setCache(result);

    return result;
}

/**
 * Batch enrich multiple IOCs
 */
export async function batchEnrichIOCs(
    values: string[],
    config: EnrichmentConfig = { sources: ['virustotal', 'geoip'] }
): Promise<{ results: EnrichedIOC[]; errors: Array<{ value: string; error: string }> }> {
    const results: EnrichedIOC[] = [];
    const errors: Array<{ value: string; error: string }> = [];

    // Process in batches to avoid overwhelming external APIs
    const batchSize = 10;

    for (let i = 0; i < values.length; i += batchSize) {
        const batch = values.slice(i, i + batchSize);

        const batchResults = await Promise.allSettled(
            batch.map(value => enrichIOC(value, config))
        );

        for (let j = 0; j < batchResults.length; j++) {
            const result = batchResults[j];
            if (result.status === 'fulfilled') {
                results.push(result.value);
            } else {
                errors.push({ value: batch[j], error: result.reason?.message || 'Unknown error' });
            }
        }
    }

    return { results, errors };
}

// ============================================================================
// Enrichment Queue (for async processing)
// ============================================================================

interface QueueItem {
    id: string;
    value: string;
    config: EnrichmentConfig;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    result?: EnrichedIOC;
    error?: string;
    createdAt: Date;
    processedAt?: Date;
}

const enrichmentQueue: QueueItem[] = [];

export function queueEnrichment(value: string, config?: EnrichmentConfig): string {
    const id = crypto.randomUUID();

    enrichmentQueue.push({
        id,
        value,
        config: config || { sources: ['virustotal', 'geoip'] },
        status: 'pending',
        createdAt: new Date(),
    });

    return id;
}

export function getQueueStatus(id: string): QueueItem | null {
    return enrichmentQueue.find(item => item.id === id) || null;
}

export function getQueueStats(): { pending: number; processing: number; completed: number; failed: number } {
    const stats = { pending: 0, processing: 0, completed: 0, failed: 0 };

    for (const item of enrichmentQueue) {
        stats[item.status]++;
    }

    return stats;
}
