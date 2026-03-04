/**
 * AI Middleware — Convenience Functions (for Nexus Scraper)
 */

import type { LLMOptions } from './types';
import { callLLM } from './callLLM';

export interface ExtractedEntities {
    threatActors?: string[];
    malwareFamilies?: string[];
    campaigns?: string[];
    vulnerabilities?: string[];
    techniques?: string[];
    targetSectors?: string[];
    countries?: string[];
}

export interface ThreatClassification {
    relevant: boolean;
    confidence: number;
    category: string;
    severity?: string;
    summary?: string;
}

/**
 * Summarize scraped content into a concise CTI-relevant summary.
 */
export async function summarizeContent(text: string, opts?: LLMOptions): Promise<string> {
    const prompt = `You are a cyber threat intelligence analyst. Summarize the following content in 2-3 concise paragraphs, focusing on:
- Threat indicators (IPs, domains, hashes, malware names)
- Threat actors and their TTPs
- Vulnerabilities and exploits mentioned
- Campaign details and attribution

Content:
${text.slice(0, 6000)}

Provide a clear, actionable summary:`;

    const result = await callLLM(prompt, { temperature: 0.2, maxTokens: 1024, ...opts });
    return result.text;
}

/**
 * Extract named entities from text (threat actors, malware families, campaigns, etc.)
 */
export async function extractEntities(text: string, opts?: LLMOptions): Promise<ExtractedEntities> {
    const prompt = `Extract all cybersecurity entities from the following text. Return JSON:
{
  "threatActors": ["actor names"],
  "malwareFamilies": ["malware names"],
  "campaigns": ["campaign names"],
  "vulnerabilities": ["CVE IDs"],
  "techniques": ["MITRE ATT&CK technique IDs"],
  "targetSectors": ["industries/sectors targeted"],
  "countries": ["countries mentioned in context"]
}

Text:
${text.slice(0, 6000)}`;

    const result = await callLLM(prompt, { temperature: 0.1, maxTokens: 1024, jsonMode: true, ...opts });

    try {
        const jsonMatch = result.text.match(/\{[\s\S]*\}/);
        return jsonMatch ? JSON.parse(jsonMatch[0]) : {};
    } catch {
        return {};
    }
}

/**
 * Classify content for threat relevance and type.
 */
export async function classifyThreat(text: string, opts?: LLMOptions): Promise<ThreatClassification> {
    const prompt = `Classify the following content for cyber threat intelligence relevance. Return JSON:
{
  "relevant": true/false,
  "confidence": 0.0-1.0,
  "category": "malware|apt|vulnerability|data-breach|phishing|ransomware|other",
  "severity": "critical|high|medium|low|informational",
  "summary": "one-line summary"
}

Text:
${text.slice(0, 4000)}`;

    const result = await callLLM(prompt, { temperature: 0.1, maxTokens: 512, jsonMode: true, ...opts });

    try {
        const jsonMatch = result.text.match(/\{[\s\S]*\}/);
        return jsonMatch ? JSON.parse(jsonMatch[0]) : { relevant: false, confidence: 0, category: 'other' };
    } catch {
        return { relevant: false, confidence: 0, category: 'other' };
    }
}
