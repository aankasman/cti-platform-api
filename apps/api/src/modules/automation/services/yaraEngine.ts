/**
 * YARA Rule Matching Engine
 *
 * Pattern-based IOC classification using YARA-like rule syntax.
 * Rules are loaded from `data/yara-rules/` and matched against IOC
 * values, enrichment data, and metadata.
 *
 * Supports:
 *   - String matching (exact, substring, case-insensitive)
 *   - Regex patterns
 *   - Hex patterns (byte sequences)
 *   - Composite conditions (AND, OR, NOT)
 *   - Rule metadata (tags, severity, description)
 */

import { createLogger } from '../../../lib/logger';

const log = createLogger('YARAEngine');

// ============================================================================
// Types
// ============================================================================

export interface YARARule {
    name: string;
    description: string;
    author: string;
    tags: string[];
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    strings: YARAString[];
    condition: string;  // simplified: 'any of them', 'all of them', '$s1 and $s2', etc.
    createdAt: string;
    enabled: boolean;
}

export interface YARAString {
    id: string;         // e.g. '$s1'
    type: 'text' | 'regex' | 'hex';
    value: string;      // the pattern
    modifiers: string[]; // 'nocase', 'wide', 'fullword'
}

export interface YARAMatch {
    rule: string;
    tags: string[];
    severity: string;
    matchedStrings: string[];
    description: string;
}

export interface ScanResult {
    input: string;
    matches: YARAMatch[];
    scannedRules: number;
    matchedRules: number;
    scanTimeMs: number;
}

// ============================================================================
// Rule Store (in-memory, loaded from files or API)
// ============================================================================

const ruleStore: Map<string, YARARule> = new Map();

// Built-in rules for common threat patterns
const BUILTIN_RULES: YARARule[] = [
    {
        name: 'malware_c2_domain',
        description: 'Detects known C2 domain patterns',
        author: 'Rinjani CTI',
        tags: ['malware', 'c2', 'command-and-control'],
        severity: 'critical',
        strings: [
            { id: '$s1', type: 'regex', value: '\\.(tk|ml|ga|cf|gq)$', modifiers: ['nocase'] },
            { id: '$s2', type: 'regex', value: '[a-z0-9]{16,}\\.[a-z]{2,4}$', modifiers: ['nocase'] },
            { id: '$s3', type: 'regex', value: '(dyndns|no-ip|afraid\\.org)', modifiers: ['nocase'] },
        ],
        condition: 'any of them',
        createdAt: new Date().toISOString(),
        enabled: true,
    },
    {
        name: 'phishing_url',
        description: 'Detects URL patterns commonly used in phishing',
        author: 'Rinjani CTI',
        tags: ['phishing', 'social-engineering'],
        severity: 'high',
        strings: [
            { id: '$s1', type: 'regex', value: '(login|signin|verify|update|secure|account).*\\.(php|html)', modifiers: ['nocase'] },
            { id: '$s2', type: 'regex', value: 'https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/', modifiers: [] },
            { id: '$s3', type: 'regex', value: '(@|%40).+\\.', modifiers: [] },
        ],
        condition: 'any of them',
        createdAt: new Date().toISOString(),
        enabled: true,
    },
    {
        name: 'cryptocurrency_miner',
        description: 'Detects cryptocurrency mining indicators',
        author: 'Rinjani CTI',
        tags: ['cryptominer', 'resource-hijacking'],
        severity: 'medium',
        strings: [
            { id: '$s1', type: 'text', value: 'stratum+tcp://', modifiers: [] },
            { id: '$s2', type: 'text', value: 'coinhive', modifiers: ['nocase'] },
            { id: '$s3', type: 'regex', value: 'xmr|monero|cryptonight', modifiers: ['nocase'] },
            { id: '$s4', type: 'regex', value: 'pool\\.(minergate|nanopool|supportxmr)', modifiers: ['nocase'] },
        ],
        condition: 'any of them',
        createdAt: new Date().toISOString(),
        enabled: true,
    },
    {
        name: 'ransomware_indicator',
        description: 'Detects ransomware-related IOCs',
        author: 'Rinjani CTI',
        tags: ['ransomware', 'extortion'],
        severity: 'critical',
        strings: [
            { id: '$s1', type: 'regex', value: '\\.(locked|encrypted|crypt|cerber|wcry|wncry|locky|zepto)$', modifiers: ['nocase'] },
            { id: '$s2', type: 'regex', value: '(tor2web|onion\\.to|onion\\.cab)', modifiers: ['nocase'] },
            { id: '$s3', type: 'text', value: 'DECRYPT_INSTRUCTION', modifiers: ['nocase'] },
        ],
        condition: 'any of them',
        createdAt: new Date().toISOString(),
        enabled: true,
    },
    {
        name: 'tor_exit_node',
        description: 'Matches known Tor exit node patterns',
        author: 'Rinjani CTI',
        tags: ['tor', 'anonymization', 'proxy'],
        severity: 'low',
        strings: [
            { id: '$s1', type: 'regex', value: '\\.onion$', modifiers: ['nocase'] },
            { id: '$s2', type: 'text', value: 'tor-exit', modifiers: ['nocase'] },
        ],
        condition: 'any of them',
        createdAt: new Date().toISOString(),
        enabled: true,
    },
    {
        name: 'suspicious_user_agent',
        description: 'Detects suspicious or malicious user-agent patterns',
        author: 'Rinjani CTI',
        tags: ['reconnaissance', 'scanner'],
        severity: 'medium',
        strings: [
            { id: '$s1', type: 'regex', value: '(sqlmap|nikto|nmap|masscan|zgrab)', modifiers: ['nocase'] },
            { id: '$s2', type: 'regex', value: '(python-requests|curl|wget|go-http-client)\\/\\d', modifiers: ['nocase'] },
            { id: '$s3', type: 'text', value: 'Mozilla/4.0 (compatible;)', modifiers: [] },
        ],
        condition: 'any of them',
        createdAt: new Date().toISOString(),
        enabled: true,
    },
];

// ============================================================================
// Engine Core
// ============================================================================

/**
 * Initialize the engine with built-in rules.
 */
export function initYARAEngine(): void {
    ruleStore.clear();
    for (const rule of BUILTIN_RULES) {
        ruleStore.set(rule.name, rule);
    }

    // Try to load custom rules from disk
    loadRulesFromDisk().catch(() => {
        log.info('No custom YARA rules directory found, using built-in rules only');
    });

    log.info(`YARA engine initialized with ${ruleStore.size} rules`);
}

/**
 * Load custom rules from the `data/yara-rules/` directory.
 */
async function loadRulesFromDisk(): Promise<void> {
    const fs = await import('fs');
    const path = await import('path');
    const rulesDir = path.resolve(process.env.YARA_RULES_DIR || 'data/yara-rules');

    if (!fs.existsSync(rulesDir)) return;

    const files = fs.readdirSync(rulesDir).filter((f: string) => f.endsWith('.json'));
    for (const file of files) {
        try {
            const content = fs.readFileSync(path.join(rulesDir, file), 'utf-8');
            const rule = JSON.parse(content) as YARARule;
            if (rule.name && rule.strings) {
                ruleStore.set(rule.name, rule);
            }
        } catch (err) {
            log.warn(`Failed to load YARA rule: ${file}`, { error: (err as Error).message });
        }
    }
}

/**
 * Match a single string definition against input.
 */
function matchString(input: string, yaraStr: YARAString): boolean {
    const nocase = yaraStr.modifiers.includes('nocase');
    const fullword = yaraStr.modifiers.includes('fullword');

    switch (yaraStr.type) {
        case 'text': {
            const haystack = nocase ? input.toLowerCase() : input;
            const needle = nocase ? yaraStr.value.toLowerCase() : yaraStr.value;
            if (fullword) {
                const regex = new RegExp(`\\b${escapeRegex(needle)}\\b`, nocase ? 'i' : '');
                return regex.test(input);
            }
            return haystack.includes(needle);
        }
        case 'regex': {
            try {
                const flags = nocase ? 'i' : '';
                const regex = new RegExp(yaraStr.value, flags);
                return regex.test(input);
            } catch {
                return false;
            }
        }
        case 'hex': {
            // Convert hex pattern to regex: "DE AD BE EF" → /\xDE\xAD\xBE\xEF/
            try {
                const hexBytes = yaraStr.value.replace(/\s/g, '');
                const pattern = hexBytes.replace(/../g, (byte) => `\\x${byte}`);
                return new RegExp(pattern).test(input);
            } catch {
                return false;
            }
        }
        default:
            return false;
    }
}

function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Evaluate a condition against matched string IDs.
 */
function evaluateCondition(condition: string, matchedIds: Set<string>, allIds: string[]): boolean {
    const trimmed = condition.trim().toLowerCase();

    if (trimmed === 'any of them') {
        return matchedIds.size > 0;
    }
    if (trimmed === 'all of them') {
        return matchedIds.size === allIds.length;
    }

    // Parse simple conditions: "$s1 and $s2", "$s1 or $s2", "not $s1"
    // Split by 'and' / 'or' and evaluate
    if (trimmed.includes(' and ')) {
        const parts = trimmed.split(/\s+and\s+/);
        return parts.every(p => {
            const id = p.trim().replace(/^not\s+/, '');
            const negated = p.trim().startsWith('not ');
            const has = matchedIds.has(id);
            return negated ? !has : has;
        });
    }
    if (trimmed.includes(' or ')) {
        const parts = trimmed.split(/\s+or\s+/);
        return parts.some(p => {
            const id = p.trim().replace(/^not\s+/, '');
            const negated = p.trim().startsWith('not ');
            const has = matchedIds.has(id);
            return negated ? !has : has;
        });
    }

    // Single variable check
    if (trimmed.startsWith('$')) {
        return matchedIds.has(trimmed);
    }

    // Numeric condition: "2 of them"
    const numMatch = trimmed.match(/^(\d+)\s+of\s+them$/);
    if (numMatch) {
        return matchedIds.size >= parseInt(numMatch[1], 10);
    }

    // Default: any match
    return matchedIds.size > 0;
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Scan an input string against all enabled rules.
 */
export function scanValue(input: string): ScanResult {
    const startTime = Date.now();
    const matches: YARAMatch[] = [];
    let scannedRules = 0;

    for (const [, rule] of ruleStore) {
        if (!rule.enabled) continue;
        scannedRules++;

        const matchedIds = new Set<string>();
        const matchedStrings: string[] = [];

        for (const str of rule.strings) {
            if (matchString(input, str)) {
                matchedIds.add(str.id);
                matchedStrings.push(str.id);
            }
        }

        const allIds = rule.strings.map(s => s.id);
        if (evaluateCondition(rule.condition, matchedIds, allIds)) {
            matches.push({
                rule: rule.name,
                tags: rule.tags,
                severity: rule.severity,
                matchedStrings,
                description: rule.description,
            });
        }
    }

    return {
        input: input.length > 200 ? input.substring(0, 200) + '...' : input,
        matches,
        scannedRules,
        matchedRules: matches.length,
        scanTimeMs: Date.now() - startTime,
    };
}

/**
 * Add a new rule to the engine.
 */
export function addRule(rule: YARARule): void {
    ruleStore.set(rule.name, rule);
    log.info(`YARA rule added: ${rule.name}`);
}

/**
 * Remove a rule by name.
 */
export function removeRule(name: string): boolean {
    const deleted = ruleStore.delete(name);
    if (deleted) log.info(`YARA rule removed: ${name}`);
    return deleted;
}

/**
 * Get all loaded rules.
 */
export function listRules(): YARARule[] {
    return Array.from(ruleStore.values());
}

/**
 * Get a rule by name.
 */
export function getRule(name: string): YARARule | undefined {
    return ruleStore.get(name);
}

/**
 * Toggle a rule's enabled state.
 */
export function toggleRule(name: string, enabled: boolean): boolean {
    const rule = ruleStore.get(name);
    if (!rule) return false;
    rule.enabled = enabled;
    return true;
}

/**
 * Batch scan: scan multiple values and return aggregated results.
 */
export function batchScan(values: string[]): {
    totalScanned: number;
    totalMatches: number;
    results: ScanResult[];
    ruleHitCounts: Record<string, number>;
} {
    const ruleHitCounts: Record<string, number> = {};
    const results: ScanResult[] = [];
    let totalMatches = 0;

    for (const value of values) {
        const result = scanValue(value);
        results.push(result);
        totalMatches += result.matchedRules;

        for (const match of result.matches) {
            ruleHitCounts[match.rule] = (ruleHitCounts[match.rule] || 0) + 1;
        }
    }

    return {
        totalScanned: values.length,
        totalMatches,
        results,
        ruleHitCounts,
    };
}

// Initialize on import
initYARAEngine();
