/**
 * Circuit Breaker for External API Calls
 *
 * Prevents cascading failures when external services (VirusTotal, AbuseIPDB, etc.)
 * are unavailable. Implements the three-state pattern:
 *
 *   CLOSED  → normal operation, requests pass through
 *   OPEN    → service is down, requests fail fast without calling
 *   HALF_OPEN → after cooldown, allow one probe request to test recovery
 *
 * Usage:
 *   const breaker = getBreaker('virustotal');
 *   const result = await breaker.call(() => fetch('https://...'));
 */

import { createLogger } from '../lib/logger';

const log = createLogger('CircuitBreaker');

// ============================================================================
// Types
// ============================================================================

export enum CircuitState {
    CLOSED = 'CLOSED',
    OPEN = 'OPEN',
    HALF_OPEN = 'HALF_OPEN',
}

export interface CircuitBreakerOptions {
    /** Number of consecutive failures before opening */
    failureThreshold: number;
    /** Milliseconds to wait before probing (OPEN → HALF_OPEN) */
    cooldownMs: number;
    /** Timeout for individual calls (ms) */
    timeoutMs: number;
    /** Number of successes in HALF_OPEN to fully close */
    successThreshold: number;
}

const DEFAULT_OPTIONS: CircuitBreakerOptions = {
    failureThreshold: 5,
    cooldownMs: 30_000,   // 30 seconds
    timeoutMs: 15_000,    // 15 seconds
    successThreshold: 2,
};

// ============================================================================
// Circuit Breaker Implementation
// ============================================================================

export class CircuitBreaker {
    readonly name: string;
    private state: CircuitState = CircuitState.CLOSED;
    private failures = 0;
    private successes = 0;
    private lastFailureTime = 0;
    private readonly options: CircuitBreakerOptions;

    constructor(name: string, options?: Partial<CircuitBreakerOptions>) {
        this.name = name;
        this.options = { ...DEFAULT_OPTIONS, ...options };
    }

    getState(): CircuitState {
        return this.state;
    }

    getStats() {
        return {
            name: this.name,
            state: this.state,
            failures: this.failures,
            successes: this.successes,
            lastFailureTime: this.lastFailureTime,
            cooldownRemaining: this.state === CircuitState.OPEN
                ? Math.max(0, this.options.cooldownMs - (Date.now() - this.lastFailureTime))
                : 0,
        };
    }

    /**
     * Execute a function through the circuit breaker
     */
    async call<T>(fn: () => Promise<T>): Promise<T> {
        // Check if circuit should transition from OPEN → HALF_OPEN
        if (this.state === CircuitState.OPEN) {
            if (Date.now() - this.lastFailureTime >= this.options.cooldownMs) {
                this.state = CircuitState.HALF_OPEN;
                this.successes = 0;
                log.info(`Circuit ${this.name}: OPEN → HALF_OPEN (probing)`);
            } else {
                throw new CircuitOpenError(this.name, this.getStats());
            }
        }

        try {
            // Apply timeout
            const result = await Promise.race([
                fn(),
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(new Error('Circuit breaker timeout')), this.options.timeoutMs)
                ),
            ]);

            this.onSuccess();
            return result;
        } catch (err) {
            this.onFailure();
            throw err;
        }
    }

    private onSuccess(): void {
        if (this.state === CircuitState.HALF_OPEN) {
            this.successes++;
            if (this.successes >= this.options.successThreshold) {
                this.state = CircuitState.CLOSED;
                this.failures = 0;
                this.successes = 0;
                log.info(`Circuit ${this.name}: HALF_OPEN → CLOSED (recovered)`);
            }
        } else {
            this.failures = 0;
        }
    }

    private onFailure(): void {
        this.failures++;
        this.lastFailureTime = Date.now();

        if (this.state === CircuitState.HALF_OPEN) {
            this.state = CircuitState.OPEN;
            log.warn(`Circuit ${this.name}: HALF_OPEN → OPEN (probe failed)`);
        } else if (this.failures >= this.options.failureThreshold) {
            this.state = CircuitState.OPEN;
            log.warn(`Circuit ${this.name}: CLOSED → OPEN (${this.failures} failures)`);
        }
    }

    /** Manual reset (admin action) */
    reset(): void {
        this.state = CircuitState.CLOSED;
        this.failures = 0;
        this.successes = 0;
        log.info(`Circuit ${this.name}: manually reset to CLOSED`);
    }
}

// ============================================================================
// Circuit Open Error
// ============================================================================

import { AppError } from './errors';

export class CircuitOpenError extends AppError {
    readonly circuitName: string;
    readonly stats: ReturnType<CircuitBreaker['getStats']>;

    constructor(name: string, stats: ReturnType<CircuitBreaker['getStats']>) {
        super(`Circuit breaker "${name}" is OPEN — service unavailable (cooldown ${Math.ceil(stats.cooldownRemaining / 1000)}s)`, {
            statusCode: 503,
            code: 'SERVICE_UNAVAILABLE',
            context: { circuit: name, ...stats },
        });
        this.circuitName = name;
        this.stats = stats;
    }
}

// ============================================================================
// Registry — one breaker per external service
// ============================================================================

const breakers = new Map<string, CircuitBreaker>();

export function getBreaker(name: string, options?: Partial<CircuitBreakerOptions>): CircuitBreaker {
    let breaker = breakers.get(name);
    if (!breaker) {
        breaker = new CircuitBreaker(name, options);
        breakers.set(name, breaker);
    }
    return breaker;
}

export function getAllBreakerStats() {
    return Array.from(breakers.values()).map(b => b.getStats());
}

export function resetAllBreakers(): void {
    breakers.forEach(b => b.reset());
}
