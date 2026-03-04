/**
 * IOC Confidence Decay — Time-Based Aging
 *
 * Implements exponential decay on IOC confidence scores based on
 * time since last observation. Older IOCs naturally lose relevance
 * unless refreshed by new reports.
 *
 * Formula:
 *   decayed_score = base_score × e^(-λ × days_since_last_seen)
 *
 * Where λ (decay rate) varies by IOC type:
 *   - IP addresses:  fast decay (IPs rotate frequently)
 *   - Domains:       medium decay
 *   - File hashes:   slow decay (hashes are immutable)
 *   - URLs:          fast decay (short-lived)
 */

import { createLogger } from '../lib/logger';

const log = createLogger('ConfidenceDecay');

// ============================================================================
// Decay Configuration
// ============================================================================

export interface DecayConfig {
    /** Decay rate λ — higher = faster decay */
    lambda: number;
    /** Minimum score floor (never decays below this) */
    minScore: number;
    /** Days after which IOC is considered stale (for cleanup) */
    staleDays: number;
}

const DECAY_RATES: Record<string, DecayConfig> = {
    'ipv4-addr': { lambda: 0.05, minScore: 10, staleDays: 30 },
    'ipv6-addr': { lambda: 0.05, minScore: 10, staleDays: 30 },
    'domain-name': { lambda: 0.03, minScore: 15, staleDays: 60 },
    'url': { lambda: 0.07, minScore: 5, staleDays: 14 },
    'file:SHA-256': { lambda: 0.01, minScore: 20, staleDays: 180 },
    'file:SHA-1': { lambda: 0.01, minScore: 20, staleDays: 180 },
    'file:MD5': { lambda: 0.015, minScore: 15, staleDays: 120 },
    'email-addr': { lambda: 0.04, minScore: 10, staleDays: 45 },
    'default': { lambda: 0.03, minScore: 10, staleDays: 60 },
};

// ============================================================================
// Decay Functions
// ============================================================================

/**
 * Calculate the decayed confidence score for an IOC
 */
export function calculateDecayedScore(
    baseScore: number,
    lastSeenDate: Date | string,
    iocType: string,
): { score: number; isStale: boolean; daysSinceLastSeen: number } {
    const config = DECAY_RATES[iocType] || DECAY_RATES['default'];
    const lastSeen = typeof lastSeenDate === 'string' ? new Date(lastSeenDate) : lastSeenDate;
    const daysSinceLastSeen = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60 * 24);

    // Exponential decay: score × e^(-λ × days)
    const decayedScore = Math.max(
        config.minScore,
        Math.round(baseScore * Math.exp(-config.lambda * daysSinceLastSeen)),
    );

    return {
        score: decayedScore,
        isStale: daysSinceLastSeen >= config.staleDays,
        daysSinceLastSeen: Math.round(daysSinceLastSeen * 10) / 10,
    };
}

/**
 * Refresh an IOC's confidence (called when a new report/sighting is received)
 */
export function refreshConfidence(
    currentScore: number,
    boostFactor: number = 1.2,
    maxScore: number = 100,
): number {
    return Math.min(maxScore, Math.round(currentScore * boostFactor));
}

/**
 * Batch-calculate decay for an array of IOCs (for scheduled maintenance)
 */
export function batchDecay(iocs: Array<{
    id: string;
    riskScore: number;
    lastSeen: string;
    type: string;
}>): Array<{
    id: string;
    originalScore: number;
    decayedScore: number;
    isStale: boolean;
    daysSinceLastSeen: number;
}> {
    return iocs.map(ioc => {
        const result = calculateDecayedScore(ioc.riskScore, ioc.lastSeen, ioc.type);
        return {
            id: ioc.id,
            originalScore: ioc.riskScore,
            decayedScore: result.score,
            isStale: result.isStale,
            daysSinceLastSeen: result.daysSinceLastSeen,
        };
    });
}

/**
 * Get decay configuration for inspection/admin
 */
export function getDecayConfig(): Record<string, DecayConfig> {
    return { ...DECAY_RATES };
}
