/**
 * AI Analysis — Prompt Templates
 */

import type { AnalysisType } from './types';

export const ANALYSIS_PROMPTS: Record<AnalysisType, (ioc: string, type?: string) => string> = {
    'threat-assessment': (ioc, type) => `
You are a threat intelligence analyst. Analyze the following indicator of compromise (IOC) and provide a threat assessment.

IOC: ${ioc}
Type: ${type || 'unknown'}

Provide your analysis in JSON format with the following structure:
{
  "severity": "low|medium|high|critical",
  "confidence": 0.0-1.0,
  "threatType": "type of threat",
  "description": "brief description of the threat",
  "recommendations": ["action 1", "action 2"],
  "ttps": ["MITRE ATT&CK TTP IDs if applicable"],
  "relatedIndicators": ["related IOCs if known"]
}
`,
    'malware-classification': (ioc, type) => `
You are a malware analyst. Classify the following indicator of compromise (IOC).

IOC: ${ioc}
Type: ${type || 'unknown'}

Provide your classification in JSON format:
{
  "family": "malware family name or 'unknown'",
  "variant": "specific variant if known",
  "confidence": 0.0-1.0,
  "behaviors": ["behavior 1", "behavior 2"],
  "capabilities": ["capability 1"],
  "associatedActors": ["threat actor names if known"]
}
`,
    'risk-score': (ioc, type) => `
You are a cybersecurity risk analyst. Calculate a risk score for this indicator of compromise (IOC).

IOC: ${ioc}
Type: ${type || 'unknown'}

Provide your risk assessment in JSON format:
{
  "score": 0-100,
  "factors": [
    { "name": "factor name", "impact": 0-100, "description": "why this affects score" }
  ],
  "mitigations": ["recommended mitigation 1", "mitigation 2"]
}
`,
    'summarization': (ioc, type) => `
Provide a brief threat intelligence summary for this IOC: ${ioc} (Type: ${type || 'unknown'})
Keep it under 200 words.
`,
    'cve-analysis': (cveData) => `
You are a vulnerability analyst and security expert. Analyze the following CVE and provide actionable intelligence.

${cveData}

Provide your analysis in JSON format:
{
  "exploitabilityScore": 0-10,
  "priorityLevel": "immediate|high|medium|low|monitor",
  "attackVector": "network|adjacent|local|physical",
  "attackComplexity": "low|medium|high",
  "impactAnalysis": "detailed description of potential impact if exploited",
  "affectedSystems": ["list of commonly affected system types"],
  "remediationSteps": ["step 1", "step 2", "step 3"],
  "workarounds": ["temporary mitigation if patch not available"],
  "relatedVulnerabilities": ["related CVE IDs"],
  "threatActors": ["known threat actors exploiting this vulnerability"]
}

Focus on practical, actionable guidance for security teams. Consider:
- Likelihood of exploitation in the wild
- Prerequisites an attacker needs
- Business impact if successfully exploited
- Time sensitivity for patching
`,
    'actor-profile': (actorData) => `
You are a threat intelligence analyst specializing in threat actor attribution and profiling. Analyze the following threat actor data.

${actorData}

Provide your analysis in JSON format:
{
  "threatLevel": "critical|high|medium|low",
  "operationalSummary": "concise summary of the actor's operations, objectives, and methods",
  "primaryTargets": ["industries or sectors this actor targets"],
  "ttpsUsed": ["MITRE ATT&CK technique IDs and names commonly used"],
  "knownCampaigns": ["notable campaigns attributed to this actor"],
  "attributionConfidence": 0.0-1.0,
  "defenseRecommendations": ["specific defensive measures against this actor"],
  "indicatorsToWatch": ["IOC types and patterns associated with this actor"],
  "relatedActors": ["affiliated or similar threat actors"]
}

Consider:
- The actor's sophistication and resources
- Their typical attack lifecycle and kill chain
- Specific defenses effective against their TTPs
- Early warning indicators of their activity
`,
};
