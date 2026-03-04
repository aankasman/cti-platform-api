/**
 * HashiCorp Vault Client — Secrets Management
 *
 * Provides a simple interface to read/write secrets from Vault.
 * Falls back to environment variables when Vault is unavailable
 * (zero-friction development without the platform profile).
 *
 * Usage:
 *   const apiKey = await secrets.get('virustotal/api-key');
 *   await secrets.set('virustotal/api-key', 'new-key');
 */

import { createLogger } from '../lib/logger';

const log = createLogger('Vault');

// ============================================================================
// Types
// ============================================================================

export interface VaultConfig {
    address: string;
    token: string;
    mountPath: string;
}

const DEFAULT_CONFIG: VaultConfig = {
    address: process.env.VAULT_ADDR || 'http://localhost:8200',
    token: process.env.VAULT_ROOT_TOKEN || 'rinjani-dev-token',
    mountPath: 'secret',
};

// ============================================================================
// Vault Client
// ============================================================================

class VaultClient {
    private config: VaultConfig;
    private available: boolean | null = null;
    private cache = new Map<string, { value: string; expiry: number }>();
    private readonly cacheTTL = 300_000; // 5 minutes

    constructor(config?: Partial<VaultConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Check if Vault is reachable
     */
    async isAvailable(): Promise<boolean> {
        if (this.available !== null) return this.available;

        try {
            const res = await fetch(`${this.config.address}/v1/sys/health`, {
                signal: AbortSignal.timeout(3000),
            });
            this.available = res.ok || res.status === 429; // 429 = standby but reachable
            log.info('Vault connectivity check', { available: this.available });
        } catch {
            this.available = false;
            log.info('Vault unavailable, using environment variables as fallback');
        }

        return this.available;
    }

    /**
     * Get a secret value. Falls back to env vars if Vault is unavailable.
     *
     * @param path - Secret path (e.g., 'virustotal/api-key')
     * @param envFallback - Environment variable name to use as fallback
     */
    async get(path: string, envFallback?: string): Promise<string | undefined> {
        // Check cache first
        const cached = this.cache.get(path);
        if (cached && cached.expiry > Date.now()) {
            return cached.value;
        }

        if (await this.isAvailable()) {
            try {
                const res = await fetch(
                    `${this.config.address}/v1/${this.config.mountPath}/data/${path}`,
                    {
                        headers: { 'X-Vault-Token': this.config.token },
                        signal: AbortSignal.timeout(5000),
                    },
                );

                if (res.ok) {
                    const body = await res.json() as { data?: { data?: { value?: string } } };
                    const value = body?.data?.data?.value;
                    if (value) {
                        this.cache.set(path, {
                            value,
                            expiry: Date.now() + this.cacheTTL,
                        });
                        return value;
                    }
                }
            } catch (err) {
                log.warn('Vault read failed, falling back', {
                    path,
                    error: (err as Error).message,
                });
            }
        }

        // Fallback to environment variable
        if (envFallback) {
            return process.env[envFallback];
        }

        // Try to derive env var name from path (e.g., 'virustotal/api-key' → 'VIRUSTOTAL_API_KEY')
        const envKey = path.replace(/[/-]/g, '_').toUpperCase();
        return process.env[envKey];
    }

    /**
     * Write a secret to Vault
     */
    async set(path: string, value: string): Promise<boolean> {
        if (!(await this.isAvailable())) {
            log.warn('Vault unavailable, cannot write secret', { path });
            return false;
        }

        try {
            const res = await fetch(
                `${this.config.address}/v1/${this.config.mountPath}/data/${path}`,
                {
                    method: 'POST',
                    headers: {
                        'X-Vault-Token': this.config.token,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ data: { value } }),
                    signal: AbortSignal.timeout(5000),
                },
            );

            if (res.ok) {
                // Update cache
                this.cache.set(path, {
                    value,
                    expiry: Date.now() + this.cacheTTL,
                });
                log.info('Secret written to Vault', { path });
                return true;
            }

            log.warn('Vault write failed', { path, status: res.status });
            return false;
        } catch (err) {
            log.error('Vault write error', { path, error: (err as Error).message });
            return false;
        }
    }

    /**
     * List all secret keys at a path
     */
    async list(path: string = ''): Promise<string[]> {
        if (!(await this.isAvailable())) return [];

        try {
            const res = await fetch(
                `${this.config.address}/v1/${this.config.mountPath}/metadata/${path}`,
                {
                    method: 'LIST',
                    headers: { 'X-Vault-Token': this.config.token },
                    signal: AbortSignal.timeout(5000),
                },
            );

            if (res.ok) {
                const body = await res.json() as { data?: { keys?: string[] } };
                return body?.data?.keys || [];
            }
        } catch {
            // Vault unavailable
        }

        return [];
    }

    /**
     * Clear the local cache
     */
    clearCache(): void {
        this.cache.clear();
    }

    /**
     * Reset availability check (useful after Vault comes back online)
     */
    resetAvailability(): void {
        this.available = null;
    }
}

// Singleton
export const secrets = new VaultClient();
