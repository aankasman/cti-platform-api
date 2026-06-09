/**
 * dnstwist-style domain permutation generator — Phase 5 #1.
 *
 * Given an apex domain like `rinjanianalytics.com`, emit the canonical
 * look-alike permutations a typo-squatter or homoglyph attacker would
 * register. The list is bounded (max ~1500 per apex for a 12-char
 * label) so the downstream DNS sweep doesn't run forever.
 *
 * Pure functions only — no I/O, no DNS. The worker that walks this
 * output and resolves each entry lives in
 * `apps/api/src/queues/workers/brandMonitorWorker.ts`.
 *
 * Algorithms implemented:
 *   bitsquat       single bit flips on each character
 *   homoglyph      visually similar substitutions (l→1, o→0, m→rn, …)
 *   insertion      adjacent QWERTY-key inserts between every pair
 *   omission       drop one character at a time
 *   substitution   replace each char with an adjacent QWERTY key
 *   transposition  swap adjacent character pairs
 *   vowel-swap     replace each vowel with every other vowel
 *   hyphenation    insert a hyphen at every position
 *   subdomain      add `<word>.` prefix from a short fixed list
 *
 * What's deliberately NOT here:
 *   - TLD swap (`.com` → `.net`/`.io`/...). The worker layers that
 *     on top by walking a TLD list so the algorithms stay
 *     SLD-focused and the test surface stays compact.
 *   - IDN/punycode. Handled by the homoglyph table (one-step
 *     visually-similar latin replacements). Full IDN/punycode
 *     generation is a follow-on.
 */

export interface Permutation {
    value: string;
    algorithm:
        | 'bitsquat' | 'homoglyph' | 'insertion' | 'omission'
        | 'substitution' | 'transposition' | 'vowel-swap'
        | 'hyphenation' | 'subdomain';
}

// QWERTY adjacency for typo-style algorithms. Lower-case only.
const QWERTY_ADJ: Record<string, string> = {
    a: 'qwsz', b: 'vghn', c: 'xdfv', d: 'serfcx', e: 'wsdr',
    f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', i: 'ujko', j: 'huikmn',
    k: 'jiolm', l: 'kop', m: 'njk', n: 'bhjm', o: 'iklp',
    p: 'ol', q: 'wa', r: 'edft', s: 'awedxz', t: 'rfgy',
    u: 'yhji', v: 'cfgb', w: 'qase', x: 'zsdc', y: 'tghu',
    z: 'asx',
};

// Visually similar pairs. Keep this conservative — false positives
// here mean a fresh wave of low-value alerts every sweep.
const HOMOGLYPH_MAP: Record<string, string[]> = {
    a: ['4', '@'], b: ['8'], e: ['3'], g: ['9'], i: ['1', 'l'],
    l: ['1', 'i'], o: ['0'], s: ['5', '$'], t: ['7'], z: ['2'],
    // Multi-char visual lookalikes go LAST in the value list so a
    // caller iterating sees the single-char swaps first.
    m: ['rn'], w: ['vv'], n: ['m'], u: ['v'],
};

const VOWELS = ['a', 'e', 'i', 'o', 'u'];

const SUBDOMAIN_PREFIXES = [
    'www', 'secure', 'login', 'account', 'support', 'mail',
];

/** Split an apex into `[label, tld]`. Throws on malformed input. */
export function splitApex(apex: string): { label: string; tld: string } {
    const trimmed = apex.trim().toLowerCase();
    if (!trimmed.includes('.')) throw new Error(`apex must include a TLD: ${apex}`);
    const idx = trimmed.lastIndexOf('.');
    const label = trimmed.slice(0, idx);
    const tld = trimmed.slice(idx + 1);
    if (!label || !tld) throw new Error(`malformed apex: ${apex}`);
    // Only flag the label-with-multiple-dots case (e.g. "co.uk"-style
    // multi-component TLDs). Handle by treating the last TWO components
    // as the TLD when the trailing label is 2 chars.
    const labelDotCount = (label.match(/\./g) ?? []).length;
    if (labelDotCount > 0 && tld.length === 2) {
        const idx2 = label.lastIndexOf('.');
        return {
            label: label.slice(0, idx2),
            tld: label.slice(idx2 + 1) + '.' + tld,
        };
    }
    return { label, tld };
}

// ── Generators (operate on the SLD label, TLD reattached at end) ──

function bitsquat(label: string): string[] {
    const out: string[] = [];
    const buf = Buffer.from(label, 'utf8');
    for (let i = 0; i < buf.length; i++) {
        for (let bit = 0; bit < 8; bit++) {
            const flipped = Buffer.from(buf);
            flipped[i] ^= 1 << bit;
            const cand = flipped.toString('utf8');
            // Reject any flip that lands outside lowercase ascii letters/digits/hyphen.
            if (/^[a-z0-9-]+$/.test(cand) && cand !== label) out.push(cand);
        }
    }
    return out;
}

function homoglyph(label: string): string[] {
    const out: string[] = [];
    for (let i = 0; i < label.length; i++) {
        const ch = label[i];
        const subs = HOMOGLYPH_MAP[ch];
        if (!subs) continue;
        for (const sub of subs) out.push(label.slice(0, i) + sub + label.slice(i + 1));
    }
    return out;
}

function insertion(label: string): string[] {
    const out: string[] = [];
    for (let i = 0; i < label.length; i++) {
        const adj = QWERTY_ADJ[label[i]];
        if (!adj) continue;
        for (const k of adj) {
            // Insert before and after the char.
            out.push(label.slice(0, i) + k + label.slice(i));
            out.push(label.slice(0, i + 1) + k + label.slice(i + 1));
        }
    }
    return out;
}

function omission(label: string): string[] {
    if (label.length <= 2) return [];
    const out: string[] = [];
    for (let i = 0; i < label.length; i++) {
        out.push(label.slice(0, i) + label.slice(i + 1));
    }
    return out;
}

function substitution(label: string): string[] {
    const out: string[] = [];
    for (let i = 0; i < label.length; i++) {
        const adj = QWERTY_ADJ[label[i]];
        if (!adj) continue;
        for (const k of adj) out.push(label.slice(0, i) + k + label.slice(i + 1));
    }
    return out;
}

function transposition(label: string): string[] {
    const out: string[] = [];
    for (let i = 0; i < label.length - 1; i++) {
        const swapped = label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2);
        if (swapped !== label) out.push(swapped);
    }
    return out;
}

function vowelSwap(label: string): string[] {
    const out: string[] = [];
    for (let i = 0; i < label.length; i++) {
        const ch = label[i];
        if (!VOWELS.includes(ch)) continue;
        for (const v of VOWELS) {
            if (v === ch) continue;
            out.push(label.slice(0, i) + v + label.slice(i + 1));
        }
    }
    return out;
}

function hyphenation(label: string): string[] {
    if (label.length <= 1) return [];
    const out: string[] = [];
    // Skip first + last positions; a hyphen at edges is invalid DNS anyway.
    for (let i = 1; i < label.length; i++) {
        if (label[i] === '-' || label[i - 1] === '-') continue;
        out.push(label.slice(0, i) + '-' + label.slice(i));
    }
    return out;
}

function subdomainPrefix(label: string): string[] {
    return SUBDOMAIN_PREFIXES.map(p => `${p}.${label}`);
}

const ALGORITHMS: Array<{ name: Permutation['algorithm']; fn: (l: string) => string[] }> = [
    { name: 'bitsquat',      fn: bitsquat },
    { name: 'homoglyph',     fn: homoglyph },
    { name: 'insertion',     fn: insertion },
    { name: 'omission',      fn: omission },
    { name: 'substitution',  fn: substitution },
    { name: 'transposition', fn: transposition },
    { name: 'vowel-swap',    fn: vowelSwap },
    { name: 'hyphenation',   fn: hyphenation },
    { name: 'subdomain',     fn: subdomainPrefix },
];

/**
 * Generate the full permutation set for an apex. Caller is responsible for:
 *   1. DNS-resolving each entry
 *   2. Dropping entries that match the apex itself
 *   3. Deduping across runs by `(monitored_domain_id, permutation)` unique
 */
export function generatePermutations(apex: string, opts: { maxPerAlgorithm?: number } = {}): Permutation[] {
    const { label, tld } = splitApex(apex);
    const cap = opts.maxPerAlgorithm ?? 500;
    const seen = new Set<string>();
    const out: Permutation[] = [];

    for (const { name, fn } of ALGORITHMS) {
        const variants = fn(label).slice(0, cap);
        for (const v of variants) {
            const full = `${v}.${tld}`;
            if (full === apex.toLowerCase() || seen.has(full)) continue;
            seen.add(full);
            out.push({ value: full, algorithm: name });
        }
    }

    return out;
}

// ── Scoring helpers (pure) ─────────────────────────────────────────

/** Standard Levenshtein. Used by the scorer. */
export function levenshtein(a: string, b: string): number {
    if (a === b) return 0;
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const prev: number[] = Array.from({ length: b.length + 1 }, (_, i) => i);
    const curr: number[] = new Array(b.length + 1);
    for (let i = 1; i <= a.length; i++) {
        curr[0] = i;
        for (let j = 1; j <= b.length; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
        }
        for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
    }
    return prev[b.length];
}

export interface ScoringInput {
    apex: string;
    permutation: string;
    dnsState: 'active' | 'mx_only' | 'nx' | 'error';
    firstSeenAt: Date;
    /** "now" override for tests. */
    now?: Date;
}

/**
 * Composite 0..100 score the dashboard sorts on. Breakdown:
 *   - +40 if dns_state in (active, mx_only)
 *   - +20 if firstSeen within last 7 days
 *   - +20 if shares same TLD as apex
 *   - +20 if Levenshtein distance from apex <= 2
 */
export function scoreAlert(input: ScoringInput): number {
    const now = input.now ?? new Date();
    let score = 0;

    if (input.dnsState === 'active' || input.dnsState === 'mx_only') score += 40;

    const ageDays = (now.getTime() - input.firstSeenAt.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays <= 7) score += 20;

    const apexTld = input.apex.toLowerCase().split('.').pop();
    const permTld = input.permutation.toLowerCase().split('.').pop();
    if (apexTld && apexTld === permTld) score += 20;

    if (levenshtein(input.apex.toLowerCase(), input.permutation.toLowerCase()) <= 2) score += 20;

    return Math.min(100, score);
}
