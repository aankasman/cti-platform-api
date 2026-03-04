/**
 * Feed Base Class
 * 
 * Abstract base class for implementing feed workers.
 * Similar to Rinjani Python worker pattern.
 */

// ============================================================================
// Types
// ============================================================================

export interface FeedConfig {
    name: string;
    description?: string;
    schedule: string;           // "30m", "6h", "1d", "7d"
    enabled: boolean;

    // Rate limiting
    rateLimit?: {
        requests: number;       // Max requests per window
        window: number;         // Window in milliseconds
    };

    // Retry configuration
    retry?: {
        maxAttempts: number;
        backoffMs: number;      // Initial backoff
        maxBackoffMs: number;   // Max backoff
    };

    // Custom settings
    settings?: Record<string, unknown>;
}

export interface FetchResult<T> {
    items: T[];
    total: number;
    cursor?: string;
    hasMore: boolean;
}

export interface TransformResult {
    entities: Record<string, unknown>[];
    relationships: Record<string, unknown>[];
    indicators: Record<string, unknown>[];
}

export interface FeedStats {
    lastRun?: Date;
    lastSuccess?: Date;
    lastError?: {
        message: string;
        timestamp: Date;
    };
    itemsProcessed: number;
    itemsFailed: number;
    avgDurationMs: number;
}

// ============================================================================
// Abstract Base Feed
// ============================================================================

export abstract class BaseFeed<TRaw = unknown, TEntity = unknown> {
    protected config: FeedConfig;
    protected stats: FeedStats = {
        itemsProcessed: 0,
        itemsFailed: 0,
        avgDurationMs: 0,
    };

    constructor(config: FeedConfig) {
        this.config = config;
    }

    // ========================================================================
    // Abstract methods - must be implemented by subclasses
    // ========================================================================

    /**
     * Fetch raw data from the external source
     */
    abstract fetch(cursor?: string): Promise<FetchResult<TRaw>>;

    /**
     * Transform raw data into normalized entities
     */
    abstract transform(raw: TRaw): TEntity | null;

    /**
     * Validate an entity before storage
     */
    abstract validate(entity: TEntity): boolean;

    /**
     * Store entities in the database
     */
    abstract store(entities: TEntity[]): Promise<number>;

    // ========================================================================
    // Lifecycle hooks - can be overridden
    // ========================================================================

    protected async onStart(): Promise<void> {
        console.log(`[${this.config.name}] Starting sync...`);
    }

    protected async onComplete(stats: { processed: number; stored: number; duration: number }): Promise<void> {
        console.log(`[${this.config.name}] Completed: ${stats.stored}/${stats.processed} items in ${stats.duration}ms`);
    }

    protected async onError(error: Error): Promise<void> {
        console.error(`[${this.config.name}] Error:`, error.message);
        this.stats.lastError = {
            message: error.message,
            timestamp: new Date(),
        };
    }

    // ========================================================================
    // Main execution
    // ========================================================================

    /**
     * Run the full sync process
     */
    async run(): Promise<FeedStats> {
        const startTime = Date.now();
        let cursor: string | undefined;
        let totalProcessed = 0;
        let totalStored = 0;

        try {
            await this.onStart();
            this.stats.lastRun = new Date();

            // Paginated fetch loop
            do {
                const result = await this.fetchWithRetry(cursor);

                // Transform and validate
                const entities: TEntity[] = [];
                for (const raw of result.items) {
                    try {
                        const entity = this.transform(raw);
                        if (entity && this.validate(entity)) {
                            entities.push(entity);
                        }
                    } catch (error) {
                        this.stats.itemsFailed++;
                    }
                }

                // Store batch
                if (entities.length > 0) {
                    const stored = await this.store(entities);
                    totalStored += stored;
                }

                totalProcessed += result.items.length;
                cursor = result.cursor;

                // Rate limiting
                if (this.config.rateLimit) {
                    await this.sleep(this.config.rateLimit.window / this.config.rateLimit.requests);
                }
            } while (cursor);

            const duration = Date.now() - startTime;
            this.stats.itemsProcessed += totalProcessed;
            this.stats.lastSuccess = new Date();
            this.updateAvgDuration(duration);

            await this.onComplete({ processed: totalProcessed, stored: totalStored, duration });

        } catch (error) {
            await this.onError(error as Error);
            throw error;
        }

        return this.stats;
    }

    /**
     * Fetch with exponential backoff retry
     */
    protected async fetchWithRetry(cursor?: string): Promise<FetchResult<TRaw>> {
        const { maxAttempts = 3, backoffMs = 1000, maxBackoffMs = 30000 } = this.config.retry || {};

        let lastError: Error | null = null;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await this.fetch(cursor);
            } catch (error) {
                lastError = error as Error;

                if (attempt < maxAttempts) {
                    const delay = Math.min(backoffMs * Math.pow(2, attempt - 1), maxBackoffMs);
                    console.log(`[${this.config.name}] Retry ${attempt}/${maxAttempts} in ${delay}ms`);
                    await this.sleep(delay);
                }
            }
        }

        throw lastError;
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    protected sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private updateAvgDuration(duration: number): void {
        if (this.stats.avgDurationMs === 0) {
            this.stats.avgDurationMs = duration;
        } else {
            // Exponential moving average
            this.stats.avgDurationMs = this.stats.avgDurationMs * 0.8 + duration * 0.2;
        }
    }

    // ========================================================================
    // Getters
    // ========================================================================

    get name(): string {
        return this.config.name;
    }

    get schedule(): string {
        return this.config.schedule;
    }

    get isEnabled(): boolean {
        return this.config.enabled;
    }

    getStats(): FeedStats {
        return { ...this.stats };
    }
}

// ============================================================================
// Feed Registry
// ============================================================================

export class FeedRegistry {
    private feeds: Map<string, BaseFeed> = new Map();

    register(feed: BaseFeed): void {
        this.feeds.set(feed.name, feed);
        console.log(`[Registry] Registered feed: ${feed.name}`);
    }

    get(name: string): BaseFeed | undefined {
        return this.feeds.get(name);
    }

    getAll(): BaseFeed[] {
        return Array.from(this.feeds.values());
    }

    getEnabled(): BaseFeed[] {
        return this.getAll().filter(f => f.isEnabled);
    }

    async runAll(): Promise<Map<string, FeedStats>> {
        const results = new Map<string, FeedStats>();

        for (const feed of this.getEnabled()) {
            try {
                const stats = await feed.run();
                results.set(feed.name, stats);
            } catch (error) {
                console.error(`[Registry] Feed ${feed.name} failed:`, (error as Error).message);
            }
        }

        return results;
    }
}

export const feedRegistry = new FeedRegistry();
