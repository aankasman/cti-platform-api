/**
 * Playbook condition DSL — Phase 4 #3.
 *
 * Pure recursive condition evaluator. Used by `evaluatePlaybooks()` to
 * decide whether a playbook fires AND by `executeAction()` to gate
 * individual steps.
 *
 * Two shape conventions are supported:
 *
 * 1. **Legacy flat shape** (kept working for existing rows):
 *    {
 *      severity: ['high', 'critical'],   // any-of
 *      source: 'alienvault',             // exact match
 *      inKev: true,                      // exact match
 *    }
 *    All clauses must hold (implicit AND). A missing eventData field
 *    is treated as a non-match — fixing the "silently skip missing
 *    fields" surprise in the old matcher.
 *
 * 2. **Operator shape** (new):
 *    {
 *      $and: [
 *        { severity: { $in: ['high', 'critical'] } },
 *        { 'enrichment.score': { $gte: 80 } },
 *        { $or: [{ inKev: true }, { exploited: true }] },
 *        { $not: { revoked: true } },
 *      ]
 *    }
 *    Supported operators: $eq $ne $in $nin $gt $gte $lt $lte
 *                         $exists $regex $and $or $not
 *
 * Dotted keys traverse nested objects: `enrichment.score` reads
 * `eventData.enrichment.score`.
 */

export type ConditionNode = Record<string, unknown>;
export type EventData = Record<string, unknown>;

const OPERATORS = new Set([
    '$eq', '$ne', '$in', '$nin', '$gt', '$gte', '$lt', '$lte',
    '$exists', '$regex', '$and', '$or', '$not',
]);

function getNested(data: EventData, key: string): unknown {
    if (!key.includes('.')) return data[key];
    const parts = key.split('.');
    let cur: unknown = data;
    for (const p of parts) {
        if (cur == null || typeof cur !== 'object') return undefined;
        cur = (cur as Record<string, unknown>)[p];
    }
    return cur;
}

function compareNum(a: unknown, b: unknown, op: '$gt' | '$gte' | '$lt' | '$lte'): boolean {
    if (typeof a !== 'number' || typeof b !== 'number') return false;
    switch (op) {
        case '$gt': return a > b;
        case '$gte': return a >= b;
        case '$lt': return a < b;
        case '$lte': return a <= b;
    }
}

function matchValue(actual: unknown, clause: unknown): boolean {
    // Plain-value short-circuit: { foo: 'bar' } means foo === 'bar'.
    // Plain-array short-circuit: { foo: [1,2] } means foo ∈ [1,2].
    if (clause === null || typeof clause !== 'object') {
        return actual === clause;
    }
    if (Array.isArray(clause)) {
        return clause.includes(actual);
    }

    // Operator object — every operator must match (AND).
    for (const [op, arg] of Object.entries(clause as Record<string, unknown>)) {
        switch (op) {
            case '$eq': if (actual !== arg) return false; break;
            case '$ne': if (actual === arg) return false; break;
            case '$in':
                if (!Array.isArray(arg) || !arg.includes(actual)) return false;
                break;
            case '$nin':
                if (!Array.isArray(arg) || arg.includes(actual)) return false;
                break;
            case '$gt': case '$gte': case '$lt': case '$lte':
                if (!compareNum(actual, arg, op)) return false;
                break;
            case '$exists': {
                const has = actual !== undefined && actual !== null;
                if (Boolean(arg) !== has) return false;
                break;
            }
            case '$regex': {
                if (typeof arg !== 'string' || typeof actual !== 'string') return false;
                try {
                    if (!new RegExp(arg).test(actual)) return false;
                } catch { return false; }
                break;
            }
            default:
                // Unknown operator → strict reject so a typo (`$gte ` with a
                // trailing space) doesn't silently accept everything.
                if (op.startsWith('$')) return false;
                // Otherwise it's a nested-object equality check; fall back to
                // a recursive matchValue on the sub-shape.
                if (typeof actual !== 'object' || actual === null) return false;
                if (!matchValue((actual as Record<string, unknown>)[op], arg)) return false;
        }
    }
    return true;
}

export function evaluateCondition(node: ConditionNode | undefined | null, data: EventData): boolean {
    if (!node || Object.keys(node).length === 0) return true;

    for (const [key, clause] of Object.entries(node)) {
        if (key === '$and') {
            if (!Array.isArray(clause)) return false;
            for (const child of clause) {
                if (!evaluateCondition(child as ConditionNode, data)) return false;
            }
            continue;
        }
        if (key === '$or') {
            if (!Array.isArray(clause) || clause.length === 0) return false;
            const anyMatch = clause.some(child => evaluateCondition(child as ConditionNode, data));
            if (!anyMatch) return false;
            continue;
        }
        if (key === '$not') {
            if (evaluateCondition(clause as ConditionNode, data)) return false;
            continue;
        }
        if (OPERATORS.has(key)) {
            // A bare operator at the root has no field to bind against —
            // reject so users get a clear error instead of silent truthy.
            return false;
        }

        const actual = getNested(data, key);
        // For legacy flat shape with a missing field: don't silently skip
        // (the old behaviour); require an explicit `$exists: false` to
        // assert absence.
        if (!matchValue(actual, clause)) return false;
    }
    return true;
}

// ============================================================================
// Step-level types (Phase 4 #3) — referenced by executeAction()
// ============================================================================

export interface PlaybookStepGuards {
    /** Optional per-step gate. If present and false, the action is skipped (not failed). */
    if?: ConditionNode;
    /** If true, action failure does NOT short-circuit the playbook. */
    continueOnError?: boolean;
    /** Optional human label for the step — surfaced in execution audit. */
    label?: string;
}
