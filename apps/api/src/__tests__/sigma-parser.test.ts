/**
 * Sigma rule parser tests — locks the field lifting + MITRE tag mapping.
 */
import { describe, it, expect } from 'vitest';
import { parseSigmaYaml, parseSigmaBundle, normalizeAttackTag } from '@rinjani/core/sigma';
import {
    SigmaIngestSchema,
    SigmaImportUrlSchema,
    SigmaListSchema,
} from '../lib/schemas';

const SAMPLE_RULE = `
title: Suspicious PowerShell Encoded Command
id: 11111111-2222-3333-4444-555555555555
description: Detects encoded PowerShell command execution
status: stable
level: high
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains: '-EncodedCommand'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
  - attack.command-and-control
references:
  - https://example.com/research
falsepositives:
  - Legitimate scripts using encoded commands
`;

const SECOND_RULE = `
title: Suspicious Curl Download
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
level: medium
detection:
  selection:
    Image|endswith: curl.exe
  condition: selection
tags:
  - attack.t1105
`;

describe('normalizeAttackTag', () => {
    it('lifts technique tags to MITRE form', () => {
        expect(normalizeAttackTag('attack.t1059')).toEqual({ technique: 'T1059' });
        expect(normalizeAttackTag('attack.t1059.001')).toEqual({ technique: 'T1059.001' });
    });
    it('lifts tactic tags', () => {
        expect(normalizeAttackTag('attack.execution')).toEqual({ tactic: 'execution' });
        expect(normalizeAttackTag('attack.command-and-control')).toEqual({ tactic: 'command-and-control' });
    });
    it('ignores non-attack tags', () => {
        expect(normalizeAttackTag('cve.2024-1234')).toEqual({});
        expect(normalizeAttackTag('detection.dfir')).toEqual({});
    });
    it('is case-insensitive', () => {
        expect(normalizeAttackTag('ATTACK.T1059')).toEqual({ technique: 'T1059' });
    });
});

describe('parseSigmaYaml', () => {
    it('parses a complete rule', () => {
        const r = parseSigmaYaml(SAMPLE_RULE);
        expect(r.uuid).toBe('11111111-2222-3333-4444-555555555555');
        expect(r.name).toBe('Suspicious PowerShell Encoded Command');
        expect(r.severity).toBe('high');
        expect(r.status).toBe('stable');
        expect(r.externalReferences).toEqual(['https://example.com/research']);
    });

    it('extracts MITRE techniques + tactics from tags', () => {
        const r = parseSigmaYaml(SAMPLE_RULE);
        expect(r.mitreTechniques).toEqual(['T1059.001']);
        expect(r.mitreTactics.sort()).toEqual(['command-and-control', 'execution']);
    });

    it('preserves the full detection block', () => {
        const r = parseSigmaYaml(SAMPLE_RULE);
        expect(r.detection.logsource).toMatchObject({ product: 'windows', service: 'powershell' });
        expect(r.detection.detection).toHaveProperty('selection');
        expect(r.detection.detection).toHaveProperty('condition', 'selection');
    });

    it('throws on missing id', () => {
        expect(() => parseSigmaYaml('title: x\ndetection: {selection: {}, condition: selection}')).toThrow(/missing required `id`/);
    });

    it('throws on missing title', () => {
        expect(() => parseSigmaYaml('id: abc\ndetection: {selection: {}, condition: selection}')).toThrow(/missing required `title`/);
    });

    it('throws on missing detection block', () => {
        expect(() => parseSigmaYaml('id: abc\ntitle: x')).toThrow(/missing required `detection`/);
    });

    it('normalises invalid level to null', () => {
        const r = parseSigmaYaml(SAMPLE_RULE.replace('level: high', 'level: bogus'));
        expect(r.severity).toBeNull();
    });
});

describe('parseSigmaBundle', () => {
    it('parses `---`-separated multi-rule bundles', () => {
        const bundle = SAMPLE_RULE + '\n---\n' + SECOND_RULE;
        const { rules, errors } = parseSigmaBundle(bundle);
        expect(rules).toHaveLength(2);
        expect(errors).toHaveLength(0);
        expect(rules[1].mitreTechniques).toEqual(['T1105']);
    });

    it('collects per-document errors without aborting', () => {
        const bundle = SAMPLE_RULE + '\n---\nid: missing-title\ndetection: {selection: {}, condition: selection}\n---\n' + SECOND_RULE;
        const { rules, errors } = parseSigmaBundle(bundle);
        expect(rules).toHaveLength(2);
        expect(errors).toHaveLength(1);
        expect(errors[0].message).toMatch(/title/);
    });
});

describe('Sigma route schemas', () => {
    it('SigmaIngestSchema requires non-empty yaml', () => {
        expect(() => SigmaIngestSchema.parse({ yaml: '' })).toThrow();
        expect(SigmaIngestSchema.parse({ yaml: 'a: 1' }).yaml).toBe('a: 1');
    });

    it('SigmaImportUrlSchema validates URL shape', () => {
        expect(() => SigmaImportUrlSchema.parse({ url: 'not-a-url' })).toThrow();
        expect(SigmaImportUrlSchema.parse({ url: 'https://example.com/rule.yml' }).url)
            .toBe('https://example.com/rule.yml');
    });

    it('SigmaListSchema applies defaults', () => {
        const r = SigmaListSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(50);
    });

    it('SigmaListSchema coerces numeric query strings', () => {
        const r = SigmaListSchema.parse({ page: '3', pageSize: '25', severity: 'high' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(25);
        expect(r.severity).toBe('high');
    });
});
