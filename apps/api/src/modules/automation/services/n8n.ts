/**
 * n8n SOAR Client — Workflow Automation Bridge
 *
 * Provides connectivity to n8n for SOAR (Security Orchestration, Automation
 * and Response) workflows. Triggers webhooks on high-severity alerts and
 * proxies workflow/execution metadata for the dashboard.
 *
 * Usage:
 *   const ok = await n8nClient.isAvailable();
 *   await n8nClient.triggerWebhook('alert-handler', payload);
 */

import { createLogger } from '../../../lib/logger';

const log = createLogger('n8n');

// ============================================================================
// Types
// ============================================================================

export interface N8nConfig {
    url: string;
    user: string;
    password: string;
}

export interface N8nWorkflow {
    id: string;
    name: string;
    active: boolean;
    createdAt: string;
    updatedAt: string;
    tags?: { id: string; name: string }[];
}

export interface N8nExecution {
    id: string;
    workflowId: string;
    finished: boolean;
    mode: string;
    startedAt: string;
    stoppedAt?: string;
    status: string;
}

// ============================================================================
// n8n Client
// ============================================================================

const DEFAULT_CONFIG: N8nConfig = {
    url: process.env.N8N_URL || 'http://localhost:5678',
    user: process.env.N8N_USER || 'admin',
    password: process.env.N8N_PASSWORD || '',
};

class N8nClient {
    private config: N8nConfig;
    private available: boolean | null = null;
    private authHeader: string;

    constructor(config?: Partial<N8nConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.authHeader = `Basic ${Buffer.from(`${this.config.user}:${this.config.password}`).toString('base64')}`;
    }

    private get baseUrl(): string {
        return this.config.url.replace(/\/$/, '');
    }

    /**
     * Check if n8n is reachable
     */
    async isAvailable(): Promise<boolean> {
        if (this.available !== null) return this.available;

        try {
            const res = await fetch(`${this.baseUrl}/healthz`, {
                signal: AbortSignal.timeout(3000),
            });
            this.available = res.ok;
            log.info('n8n connectivity check', { available: this.available });
        } catch {
            this.available = false;
            log.info('n8n unavailable (SOAR workflows disabled)');
        }

        return this.available;
    }

    /**
     * Make an authenticated API request to n8n
     */
    private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
        const res = await fetch(`${this.baseUrl}${path}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': this.authHeader,
                ...options.headers,
            },
            signal: AbortSignal.timeout(10_000),
        });

        if (!res.ok) {
            const body = await res.text();
            throw new Error(`n8n API error ${res.status}: ${body}`);
        }

        return res.json() as Promise<T>;
    }

    /**
     * List all workflows
     */
    async getWorkflows(): Promise<N8nWorkflow[]> {
        if (!(await this.isAvailable())) return [];

        try {
            const result = await this.request<{ data: N8nWorkflow[] }>('/api/v1/workflows');
            return result.data || [];
        } catch (err) {
            log.warn('Failed to list n8n workflows', { error: (err as Error).message });
            return [];
        }
    }

    /**
     * List recent executions
     */
    async getExecutions(limit = 20): Promise<N8nExecution[]> {
        if (!(await this.isAvailable())) return [];

        try {
            const result = await this.request<{ data: N8nExecution[] }>(
                `/api/v1/executions?limit=${limit}`
            );
            return result.data || [];
        } catch (err) {
            log.warn('Failed to list n8n executions', { error: (err as Error).message });
            return [];
        }
    }

    /**
     * Trigger an n8n webhook
     *
     * @param webhookPath - The webhook path/slug configured in n8n
     * @param payload - JSON payload to send
     */
    async triggerWebhook(webhookPath: string, payload: Record<string, unknown>): Promise<boolean> {
        if (!(await this.isAvailable())) return false;

        try {
            const res = await fetch(`${this.baseUrl}/webhook/${webhookPath}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(10_000),
            });

            if (res.ok) {
                log.info('n8n webhook triggered', { webhookPath });
                return true;
            }

            log.warn('n8n webhook failed', { webhookPath, status: res.status });
            return false;
        } catch (err) {
            log.warn('n8n webhook error', { webhookPath, error: (err as Error).message });
            return false;
        }
    }

    /**
     * Reset availability check (useful after n8n comes back online)
     */
    resetAvailability(): void {
        this.available = null;
    }
}

// Singleton
export const n8nClient = new N8nClient();
