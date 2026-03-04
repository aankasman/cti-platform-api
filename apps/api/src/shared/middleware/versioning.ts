/**
 * API Versioning Middleware
 * 
 * Adds API versioning headers and handles deprecation notices.
 * Supports sunset headers for deprecated endpoints.
 */

import type { Context, Next } from 'hono';

// ============================================================================
// Configuration
// ============================================================================

export interface VersionConfig {
    current: string;
    minimum: string;
    deprecated?: string[];
    sunset?: Record<string, Date>;
}

const API_VERSIONS: VersionConfig = {
    current: '2.0',
    minimum: '1.0',
    deprecated: ['1.0'],
    sunset: {
        // Example: v1 endpoints will sunset on this date
        'v1': new Date('2026-06-01'),
    },
};

// Deprecated endpoints with replacement info
const DEPRECATED_ENDPOINTS: Record<string, { replacement: string; sunsetDate: Date }> = {
    // v1 endpoints being replaced by v2
    '/v1/threats': { replacement: '/v2/threats', sunsetDate: new Date('2026-06-01') },
    '/v1/indicators': { replacement: '/v2/indicators', sunsetDate: new Date('2026-06-01') },
    '/v1/export': { replacement: '/v2/bulk/export/iocs', sunsetDate: new Date('2026-06-01') },
};

// ============================================================================
// Middleware
// ============================================================================

/**
 * API versioning middleware
 * Adds version headers and deprecation notices
 */
export function apiVersioning() {
    return async (c: Context, next: Next) => {
        const path = c.req.path;

        // Add standard version headers
        c.header('X-API-Version', API_VERSIONS.current);
        c.header('X-API-Min-Version', API_VERSIONS.minimum);

        // Determine version from path
        const versionMatch = path.match(/^\/(v\d+)/);
        const requestVersion = versionMatch ? versionMatch[1] : null;

        // Check for deprecated version
        if (requestVersion && API_VERSIONS.deprecated?.includes(requestVersion.replace('v', '') + '.0')) {
            c.header('Deprecation', 'true');
            c.header('X-Deprecation-Notice', `API ${requestVersion} is deprecated. Please migrate to v2.`);

            const sunsetDate = API_VERSIONS.sunset?.[requestVersion];
            if (sunsetDate) {
                c.header('Sunset', sunsetDate.toUTCString());
            }
        }

        // Check for specific deprecated endpoint
        const deprecationInfo = DEPRECATED_ENDPOINTS[path];
        if (deprecationInfo) {
            c.header('Deprecation', 'true');
            c.header('Link', `<${deprecationInfo.replacement}>; rel="successor-version"`);
            c.header('Sunset', deprecationInfo.sunsetDate.toUTCString());
            c.header('X-Deprecation-Notice', `This endpoint is deprecated. Use ${deprecationInfo.replacement} instead.`);
        }

        await next();
    };
}

/**
 * Version negotiation middleware
 * Handles Accept-Version header for content negotiation
 */
export function versionNegotiation() {
    return async (c: Context, next: Next) => {
        const acceptVersion = c.req.header('Accept-Version');

        if (acceptVersion) {
            const requestedVersion = parseFloat(acceptVersion);
            const minVersion = parseFloat(API_VERSIONS.minimum);
            const currentVersion = parseFloat(API_VERSIONS.current);

            if (requestedVersion < minVersion) {
                return c.json({
                    success: false,
                    error: {
                        code: 'VERSION_NOT_SUPPORTED',
                        message: `API version ${acceptVersion} is no longer supported. Minimum supported version is ${API_VERSIONS.minimum}`,
                        supportedVersions: {
                            minimum: API_VERSIONS.minimum,
                            current: API_VERSIONS.current,
                        },
                    },
                }, 400);
            }

            if (requestedVersion > currentVersion) {
                return c.json({
                    success: false,
                    error: {
                        code: 'VERSION_NOT_FOUND',
                        message: `API version ${acceptVersion} does not exist. Current version is ${API_VERSIONS.current}`,
                    },
                }, 400);
            }

            c.header('X-Requested-Version', acceptVersion);
        }

        await next();
    };
}

// ============================================================================
// Version Info Endpoint Helper
// ============================================================================

export function getVersionInfo() {
    const now = new Date();

    return {
        versions: {
            current: API_VERSIONS.current,
            minimum: API_VERSIONS.minimum,
            deprecated: API_VERSIONS.deprecated,
        },
        endpoints: {
            v1: {
                status: 'deprecated',
                sunsetDate: API_VERSIONS.sunset?.['v1']?.toISOString(),
                documentation: '/api-docs',
            },
            v2: {
                status: 'stable',
                documentation: '/api-docs',
            },
        },
        deprecationNotices: Object.entries(DEPRECATED_ENDPOINTS).map(([path, info]) => ({
            path,
            replacement: info.replacement,
            sunsetDate: info.sunsetDate.toISOString(),
            daysUntilSunset: Math.ceil((info.sunsetDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)),
        })),
    };
}
