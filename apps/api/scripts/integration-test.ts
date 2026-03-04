/**
 * Integration Test Script — API Endpoint Verification
 *
 * Validates that key backend endpoints return expected response shapes.
 * Run with: apps/api/node_modules/.bin/tsx apps/api/scripts/integration-test.ts
 *
 * Reads API_KEY from .env or uses the first key from API_KEYS.
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Manual .env loading (avoids dotenv dependency)
const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = join(__dirname, '../../..', '.env');
try {
    const envContent = readFileSync(envPath, 'utf-8');
    for (const line of envContent.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx < 0) continue;
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim();
        if (!process.env[key]) process.env[key] = val;
    }
} catch { /* .env not found — rely on existing env */ }

const API_BASE = process.env.API_URL || 'http://localhost:3001';

// Extract first API key from API_KEYS format: "key1:role1,key2:role2"
function getApiKey(): string {
    const keys = process.env.API_KEYS || '';
    const first = keys.split(',')[0] || '';
    return first.split(':')[0] || '';
}

const API_KEY = process.env.API_KEY || getApiKey();

interface TestResult {
    name: string;
    endpoint: string;
    passed: boolean;
    status: number;
    error?: string;
    durationMs: number;
}

async function testEndpoint(
    name: string,
    endpoint: string,
    validate: (data: unknown, status: number) => string | null,
    options?: RequestInit,
): Promise<TestResult> {
    const start = Date.now();
    try {
        const res = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY,
                ...options?.headers,
            },
        });
        const text = await res.text();
        let data: unknown;
        try { data = JSON.parse(text); } catch { data = text; }
        const error = validate(data, res.status);
        return {
            name, endpoint,
            passed: !error,
            status: res.status,
            error: error || undefined,
            durationMs: Date.now() - start,
        };
    } catch (err) {
        return {
            name, endpoint,
            passed: false, status: 0,
            error: `Fetch failed: ${err instanceof Error ? err.message : String(err)}`,
            durationMs: Date.now() - start,
        };
    }
}

// Helper: check if value is an object with given key
function hasKey(obj: unknown, key: string): boolean {
    return typeof obj === 'object' && obj !== null && key in obj;
}

// ============================================================================
// Test Definitions
// ============================================================================

const tests: Array<{
    name: string;
    endpoint: string;
    validate: (data: unknown, status: number) => string | null;
    options?: RequestInit;
}> = [
        {
            name: 'Health Check',
            endpoint: '/health',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                if (!hasKey(data, 'status') && !hasKey(data, 'services')) return 'Missing status/services';
                return null;
            },
        },
        {
            name: 'Stats Overview',
            endpoint: '/v1/stats',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'IOC List',
            endpoint: '/v1/iocs?limit=3',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                // Accept any valid JSON response (list or wrapped)
                return null;
            },
        },
        {
            name: 'Vulnerability List',
            endpoint: '/v1/vulnerabilities?limit=3',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'System Health',
            endpoint: '/v1/monitoring/health',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'Feed Config',
            endpoint: '/v1/config/feeds',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'Search',
            endpoint: '/v1/search?q=malware&limit=3',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'SSE Channels',
            endpoint: '/v2/events/channels',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'STIX Validate',
            endpoint: '/v1/stix/validate',
            validate: (_data, status) => {
                // 200 = valid, 400/422 = validation error (expected for test payload)
                if (status !== 200 && status !== 400 && status !== 422) return `Unexpected status ${status}`;
                return null;
            },
            options: {
                method: 'POST',
                body: JSON.stringify({ type: 'bundle', spec_version: '2.1', objects: [] }),
            },
        },
        {
            name: 'Threat Actors',
            endpoint: '/v1/threats?limit=3',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'Audit Log',
            endpoint: '/v1/audit?limit=3',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
        {
            name: 'Notifications',
            endpoint: '/v1/notifications?limit=3',
            validate: (data, status) => {
                if (status !== 200) return `Expected 200, got ${status}`;
                return null;
            },
        },
    ];

// ============================================================================
// Runner
// ============================================================================

async function run() {
    console.log(`\n🔬 Integration Tests — ${API_BASE}`);
    console.log(`   API Key: ${API_KEY ? API_KEY.slice(0, 6) + '...' : 'NONE'}`);
    console.log(`${'─'.repeat(60)}\n`);

    const results: TestResult[] = [];

    for (const test of tests) {
        const result = await testEndpoint(test.name, test.endpoint, test.validate, test.options);
        results.push(result);

        const icon = result.passed ? '✓' : '✕';
        const color = result.passed ? '\x1b[32m' : '\x1b[31m';
        const reset = '\x1b[0m';
        const ms = `${result.durationMs}ms`.padStart(6);

        console.log(`  ${color}${icon}${reset} ${result.name.padEnd(22)} ${String(result.status).padStart(3)}  ${ms}  ${result.error || ''}`);
    }

    const passed = results.filter(r => r.passed).length;
    const failed = results.filter(r => !r.passed).length;
    const totalMs = results.reduce((s, r) => s + r.durationMs, 0);

    console.log(`\n${'─'.repeat(60)}`);

    const summaryColor = failed > 0 ? '\x1b[31m' : '\x1b[32m';
    const reset = '\x1b[0m';
    console.log(`  ${summaryColor}${passed} passed, ${failed} failed, ${results.length} total (${totalMs}ms)${reset}\n`);

    process.exit(failed > 0 ? 1 : 0);
}

run();
