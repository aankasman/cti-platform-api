/**
 * Sigma rule parsing + normalization.
 *
 * Pure helpers — no DB, no fetch. Takes a Sigma YAML string (the upstream
 * SigmaHQ format) and produces a typed object aligned with our
 * `detection_rules` table. Also maps Sigma's `attack.*` tag convention
 * onto MITRE ATT&CK technique IDs so rules can be filtered by technique.
 *
 * Spec: https://github.com/SigmaHQ/sigma-specification
 */
import { parse as parseYaml } from 'yaml';

export type SigmaLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type SigmaStatus = 'stable' | 'test' | 'experimental' | 'deprecated' | 'unsupported';

/** Parsed Sigma rule ready to upsert into `detection_rules`. */
export interface ParsedSigmaRule {
    /** Sigma `id` — required by the spec. Used as our `uuid` PK. */
    uuid: string;
    /** Sigma `title`. */
    name: string;
    /** Sigma `description`. */
    description: string | null;
    /** Sigma `level`. */
    severity: SigmaLevel | null;
    /** Sigma `status`. */
    status: SigmaStatus | null;
    /** Raw tags as they appear in the YAML, lower-cased. */
    tags: string[];
    /**
     * Detection logic. We keep the original `detection:` block verbatim so
     * downstream backends (Splunk, Elastic, etc.) can convert it; we also
     * stash `logsource` here for query-time filtering.
     */
    detection: {
        logsource: Record<string, unknown>;
        detection: Record<string, unknown>;
        fields?: string[];
        falsepositives?: string[];
    };
    /**
     * Full meta — `author`, `references`, `date`, `modified`,
     * `related`, plus any vendor-specific keys we didn't pull into a
     * first-class column. Allows lossless round-tripping back to YAML.
     */
    meta: Record<string, unknown>;
    /** Sigma `references:` list, surfaced here for the UI. */
    externalReferences: string[];
    /**
     * MITRE ATT&CK techniques derived from `attack.tNNNN` tags. Used to
     * power /v1/sigma/by-technique/:techniqueId without re-parsing tags
     * on every query.
     */
    mitreTechniques: string[];
    /** MITRE ATT&CK tactics derived from `attack.tactic-name` tags. */
    mitreTactics: string[];
}

const VALID_LEVELS: ReadonlySet<string> = new Set(['informational', 'low', 'medium', 'high', 'critical']);
const VALID_STATUSES: ReadonlySet<string> = new Set(['stable', 'test', 'experimental', 'deprecated', 'unsupported']);

/**
 * Sigma uses lower-case kebab-case tactic names that *don't* always match
 * MITRE's canonical hyphenated form. Mapping straight from
 * sigma-specification §Tags. Anything not in this table is still surfaced
 * as a raw tag — we just don't treat it as a tactic.
 */
const SIGMA_TACTIC_TO_MITRE: Record<string, string> = {
    'reconnaissance': 'reconnaissance',
    'resource-development': 'resource-development',
    'initial-access': 'initial-access',
    'execution': 'execution',
    'persistence': 'persistence',
    'privilege-escalation': 'privilege-escalation',
    'defense-evasion': 'defense-evasion',
    'credential-access': 'credential-access',
    'discovery': 'discovery',
    'lateral-movement': 'lateral-movement',
    'collection': 'collection',
    'command-and-control': 'command-and-control',
    'exfiltration': 'exfiltration',
    'impact': 'impact',
};

/**
 * Convert a Sigma tag to MITRE form.
 *
 * Sigma uses `attack.tNNNN` (lower-cased) where MITRE uses `TNNNN`
 * (upper-cased). Sub-techniques use `attack.tNNNN.NNN` → `TNNNN.NNN`.
 * For tactics, Sigma uses `attack.<kebab-name>`.
 */
export function normalizeAttackTag(tag: string): { technique?: string; tactic?: string } {
    const t = tag.trim().toLowerCase();
    if (!t.startsWith('attack.')) return {};
    const body = t.slice('attack.'.length);
    const techniqueMatch = body.match(/^t(\d{4}(?:\.\d{3})?)$/);
    if (techniqueMatch) {
        return { technique: `T${techniqueMatch[1].toUpperCase()}` };
    }
    if (body in SIGMA_TACTIC_TO_MITRE) {
        return { tactic: SIGMA_TACTIC_TO_MITRE[body] };
    }
    return {};
}

/**
 * Parse a Sigma rule YAML string and lift the fields we store relationally.
 * Throws if the YAML is malformed, missing `id`, `title`, or `detection`.
 */
export function parseSigmaYaml(yamlText: string): ParsedSigmaRule {
    const raw = parseYaml(yamlText);
    if (!raw || typeof raw !== 'object') {
        throw new Error('Sigma rule YAML did not parse to an object');
    }
    const r = raw as Record<string, unknown>;

    if (typeof r.id !== 'string' || !r.id) throw new Error('Sigma rule missing required `id`');
    if (typeof r.title !== 'string' || !r.title) throw new Error('Sigma rule missing required `title`');
    if (!r.detection || typeof r.detection !== 'object') {
        throw new Error('Sigma rule missing required `detection` block');
    }

    const level = typeof r.level === 'string' && VALID_LEVELS.has(r.level) ? (r.level as SigmaLevel) : null;
    const status = typeof r.status === 'string' && VALID_STATUSES.has(r.status) ? (r.status as SigmaStatus) : null;
    const tags = Array.isArray(r.tags) ? r.tags.filter((t): t is string => typeof t === 'string').map(t => t.toLowerCase()) : [];

    const mitreTechniques: string[] = [];
    const mitreTactics: string[] = [];
    for (const tag of tags) {
        const { technique, tactic } = normalizeAttackTag(tag);
        if (technique) mitreTechniques.push(technique);
        if (tactic) mitreTactics.push(tactic);
    }

    const references = Array.isArray(r.references)
        ? r.references.filter((x): x is string => typeof x === 'string')
        : [];

    return {
        uuid: r.id,
        name: r.title,
        description: typeof r.description === 'string' ? r.description : null,
        severity: level,
        status,
        tags,
        detection: {
            logsource: (r.logsource && typeof r.logsource === 'object') ? r.logsource as Record<string, unknown> : {},
            detection: r.detection as Record<string, unknown>,
            fields: Array.isArray(r.fields) ? r.fields.filter((x): x is string => typeof x === 'string') : undefined,
            falsepositives: Array.isArray(r.falsepositives) ? r.falsepositives.filter((x): x is string => typeof x === 'string') : undefined,
        },
        meta: r,
        externalReferences: references,
        mitreTechniques: [...new Set(mitreTechniques)],
        mitreTactics: [...new Set(mitreTactics)],
    };
}

/**
 * SigmaHQ ships a single .yml file per rule. When users upload a bundle,
 * it's typically several rules concatenated with `---` document separators.
 * This helper splits and parses, returning successes + per-doc errors.
 */
export function parseSigmaBundle(yamlText: string): {
    rules: ParsedSigmaRule[];
    errors: Array<{ index: number; message: string }>;
} {
    const docs = yamlText.split(/^---\s*$/m).map(s => s.trim()).filter(Boolean);
    const rules: ParsedSigmaRule[] = [];
    const errors: Array<{ index: number; message: string }> = [];

    docs.forEach((doc, i) => {
        try {
            rules.push(parseSigmaYaml(doc));
        } catch (err) {
            errors.push({ index: i, message: (err as Error).message });
        }
    });

    return { rules, errors };
}
