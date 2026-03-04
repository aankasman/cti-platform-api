/**
 * Worker SDK - Feed Worker Base Classes and Utilities
 * 
 * This SDK provides everything needed to create custom feed workers:
 * - Abstract base classes
 * - Type definitions
 * - Utility functions
 * - Database helpers
 */

// ============================================================================
// Types
// ============================================================================

export interface FeedConfig {
    name: string;
    schedule: string;           // Cron expression or interval string
    enabled: boolean;
    apiKey?: string;
    baseUrl?: string;
    rateLimit?: number;         // Requests per minute
    retryAttempts?: number;
    retryDelay?: number;        // Milliseconds
    batchSize?: number;
}

export interface FeedResult<T = unknown> {
    success: boolean;
    data: T[];
    processed: number;
    failed: number;
    errors: string[];
    duration: number;           // Milliseconds
    timestamp: Date;
}

export interface FetchOptions {
    page?: number;
    limit?: number;
    since?: Date;
    cursor?: string;
}

export interface TransformContext {
    source: string;
    fetchedAt: Date;
}

// ============================================================================
// Abstract Feed Worker
// ============================================================================

export abstract class FeedWorker<TInput = unknown, TOutput = unknown> {
    abstract readonly name: string;
    abstract readonly version: string;

    protected config: FeedConfig;

    constructor(config: Partial<FeedConfig> = {}) {
        this.config = {
            name: config.name || 'unnamed-worker',
            schedule: '0 */6 * * *',    // Every 6 hours by default
            enabled: true,
            retryAttempts: 3,
            retryDelay: 1000,
            batchSize: 100,
            ...config,
        };
    }

    // ========================================================================
    // Abstract methods - must be implemented
    // ========================================================================

    /**
     * Fetch data from the external source
     */
    abstract fetch(options?: FetchOptions): Promise<TInput[]>;

    /**
     * Transform raw data into normalized entities
     */
    abstract transform(data: TInput[], ctx: TransformContext): TOutput[];

    // ========================================================================
    // Optional hooks - can be overridden
    // ========================================================================

    /**
     * Called before sync starts
     */
    async beforeSync(): Promise<void> { }

    /**
     * Called after sync completes
     */
    async afterSync(result: FeedResult<TOutput>): Promise<void> { }

    /**
     * Validate a single item
     */
    validate(item: TOutput): boolean {
        return item !== null && item !== undefined;
    }

    /**
     * Store items in the database
     */
    async store(items: TOutput[]): Promise<number> {
        // Default implementation - override for custom storage
        console.log(`[${this.name}] Would store ${items.length} items (override store() to persist)`);
        return items.length;
    }

    // ========================================================================
    // Core sync logic
    // ========================================================================

    /**
     * Execute full sync with retry logic
     */
    async sync(options?: FetchOptions): Promise<FeedResult<TOutput>> {
        const startTime = Date.now();
        const result: FeedResult<TOutput> = {
            success: false,
            data: [],
            processed: 0,
            failed: 0,
            errors: [],
            duration: 0,
            timestamp: new Date(),
        };

        try {
            await this.beforeSync();

            // Fetch with retry
            let rawData: TInput[] = [];
            let lastError: Error | null = null;

            for (let attempt = 1; attempt <= (this.config.retryAttempts || 3); attempt++) {
                try {
                    rawData = await this.fetch(options);
                    break;
                } catch (error) {
                    lastError = error as Error;
                    console.warn(`[${this.name}] Fetch attempt ${attempt} failed:`, error);

                    if (attempt < (this.config.retryAttempts || 3)) {
                        const delay = (this.config.retryDelay || 1000) * Math.pow(2, attempt - 1);
                        await this.sleep(delay);
                    }
                }
            }

            if (rawData.length === 0 && lastError) {
                throw lastError;
            }

            // Transform
            const ctx: TransformContext = {
                source: this.name,
                fetchedAt: new Date(),
            };
            const transformed = this.transform(rawData, ctx);

            // Validate and filter
            const valid: TOutput[] = [];
            for (const item of transformed) {
                try {
                    if (this.validate(item)) {
                        valid.push(item);
                    } else {
                        result.failed++;
                    }
                } catch (error) {
                    result.failed++;
                    result.errors.push(`Validation error: ${error}`);
                }
            }

            // Store in batches
            const batchSize = this.config.batchSize || 100;
            for (let i = 0; i < valid.length; i += batchSize) {
                const batch = valid.slice(i, i + batchSize);
                try {
                    await this.store(batch);
                    result.processed += batch.length;
                } catch (error) {
                    result.failed += batch.length;
                    result.errors.push(`Store error: ${error}`);
                }
            }

            result.data = valid;
            result.success = result.failed === 0;

        } catch (error) {
            result.errors.push(`Sync failed: ${error}`);
        } finally {
            result.duration = Date.now() - startTime;
            result.timestamp = new Date();
            await this.afterSync(result);
        }

        return result;
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    protected sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    protected async fetchWithRateLimit(
        url: string,
        options: RequestInit = {}
    ): Promise<Response> {
        // Simple rate limiting - wait before request if needed
        if (this.config.rateLimit) {
            const delay = 60000 / this.config.rateLimit;
            await this.sleep(delay);
        }

        return fetch(url, {
            ...options,
            headers: {
                'Accept': 'application/json',
                'User-Agent': `FeedWorker/${this.version}`,
                ...options.headers,
            },
        });
    }

    protected parseDate(value: string | Date | null | undefined): Date | null {
        if (!value) return null;
        if (value instanceof Date) return value;
        try {
            return new Date(value);
        } catch {
            return null;
        }
    }

    protected sanitizeString(value: unknown): string | null {
        if (value === null || value === undefined) return null;
        return String(value).trim();
    }

    protected toArray<T>(value: T | T[] | null | undefined): T[] {
        if (!value) return [];
        return Array.isArray(value) ? value : [value];
    }
}

// ============================================================================
// Specialized Base Classes
// ============================================================================

/**
 * Base class for IOC Feeds (indicators of compromise)
 */
export abstract class IOCFeedWorker extends FeedWorker<unknown, IOCEntity> {
    abstract mapIOCType(rawType: string): string;
}

export interface IOCEntity {
    type: string;           // ip, domain, url, hash, email
    value: string;
    source: string;
    tags?: string[];
    threatType?: string;    // c2, malware, phishing, botnet
    confidence?: number;    // 0-100
    firstSeen?: Date | null;
    lastSeen?: Date | null;
    metadata?: Record<string, unknown>;
}

/**
 * Base class for Vulnerability Feeds (CVE/KEV)
 */
export abstract class VulnerabilityFeedWorker extends FeedWorker<unknown, VulnerabilityEntity> { }

export interface VulnerabilityEntity {
    cveId: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
    cvssScore?: number;
    isExploited: boolean;
    exploitAddedDate?: string | null;
    vendorProject?: string | null;
    product?: string | null;
    dueDate?: string | null;
    references?: string[];
    metadata?: Record<string, unknown>;
}

/**
 * Base class for Threat Intelligence Feeds (actors, campaigns)
 */
export abstract class ThreatIntelFeedWorker extends FeedWorker<unknown, ThreatEntity> { }

export interface ThreatEntity {
    type: 'actor' | 'campaign' | 'malware' | 'tool';
    name: string;
    description?: string | null;
    aliases?: string[];
    firstSeen?: Date | null;
    lastSeen?: Date | null;
    country?: string | null;
    motivation?: string | null;
    sophistication?: string | null;
    ttps?: string[];        // MITRE ATT&CK technique IDs
    metadata?: Record<string, unknown>;
}

// ============================================================================
// Exports
// ============================================================================

export default {
    FeedWorker,
    IOCFeedWorker,
    VulnerabilityFeedWorker,
    ThreatIntelFeedWorker,
};
