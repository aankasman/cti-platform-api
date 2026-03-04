/**
 * AI Analysis — Provider Configuration & API Calls
 */

import { createLogger } from '../../lib/logger';

const log = createLogger('AIAnalysis');

// ============================================================================
// AI Provider Configuration
// ============================================================================

export interface AIProviderConfig {
    name: string;
    apiKey: string | undefined;
    endpoint: string;
    model: string;
}

const AI_PROVIDERS: Record<string, AIProviderConfig> = {
    gemini: {
        name: 'Gemini',
        apiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY,
        endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
        model: 'gemini-2.0-flash',
    },
    openai: {
        name: 'OpenAI',
        apiKey: process.env.OPENAI_API_KEY,
        endpoint: 'https://api.openai.com/v1/chat/completions',
        model: 'gpt-4o-mini',
    },
    anthropic: {
        name: 'Anthropic',
        apiKey: process.env.ANTHROPIC_API_KEY,
        endpoint: 'https://api.anthropic.com/v1/messages',
        model: 'claude-3-haiku-20240307',
    },
    ollama: {
        name: 'Ollama (Local)',
        apiKey: undefined,
        endpoint: process.env.OLLAMA_URL || 'http://localhost:11434/api/generate',
        model: process.env.OLLAMA_MODEL || 'llama3.2',
    },
};

export function getActiveProvider(): AIProviderConfig {
    // Priority: Gemini > OpenAI > Anthropic > Ollama
    if (AI_PROVIDERS.gemini.apiKey) return AI_PROVIDERS.gemini;
    if (AI_PROVIDERS.openai.apiKey) return AI_PROVIDERS.openai;
    if (AI_PROVIDERS.anthropic.apiKey) return AI_PROVIDERS.anthropic;
    return AI_PROVIDERS.ollama;
}

// ============================================================================
// Provider API Calls
// ============================================================================

/**
 * Call Google Gemini API
 */
export async function callGemini(provider: AIProviderConfig, prompt: string): Promise<{ response: string; tokensUsed: number }> {
    const url = `${provider.endpoint}/${provider.model}:generateContent?key=${provider.apiKey}`;

    const res = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 2048,
            },
        }),
    });

    if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`Gemini API error: ${res.status} - ${errorText}`);
    }

    const data: any = await res.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const tokensUsed = (data.usageMetadata?.promptTokenCount || 0) + (data.usageMetadata?.candidatesTokenCount || 0);

    return { response: text, tokensUsed };
}

/**
 * Call OpenAI API
 */
export async function callOpenAI(provider: AIProviderConfig, prompt: string): Promise<{ response: string; tokensUsed: number }> {
    const res = await fetch(provider.endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${provider.apiKey}`,
        },
        body: JSON.stringify({
            model: provider.model,
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.3,
        }),
    });

    if (!res.ok) throw new Error(`OpenAI API error: ${res.status}`);

    const data: any = await res.json();
    return {
        response: data.choices[0]?.message?.content || '',
        tokensUsed: data.usage?.total_tokens || 0,
    };
}

/**
 * Call Anthropic API
 */
export async function callAnthropic(provider: AIProviderConfig, prompt: string): Promise<{ response: string; tokensUsed: number }> {
    const res = await fetch(provider.endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': provider.apiKey!,
            'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
            model: provider.model,
            max_tokens: 1024,
            messages: [{ role: 'user', content: prompt }],
        }),
    });

    if (!res.ok) throw new Error(`Anthropic API error: ${res.status}`);

    const data: any = await res.json();
    return {
        response: data.content[0]?.text || '',
        tokensUsed: (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0),
    };
}

/**
 * Call Ollama (local) API
 */
export async function callOllama(provider: AIProviderConfig, prompt: string): Promise<{ response: string }> {
    try {
        const res = await fetch(provider.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: provider.model,
                prompt,
                stream: false,
            }),
        });

        if (!res.ok) throw new Error(`Ollama API error: ${res.status}`);

        const data: any = await res.json();
        return { response: data.response || '' };
    } catch (err) {
        // Fallback to mock response if Ollama not available
        log.info('Ollama not available, using mock response');
        return { response: getMockResponse(prompt) };
    }
}

// ============================================================================
// Mock Response (fallback when no AI provider available)
// ============================================================================

export function getMockResponse(prompt: string): string {
    if (prompt.includes('threat-assessment') || prompt.includes('IOC:')) {
        return JSON.stringify({
            severity: 'medium',
            confidence: 0.7,
            threatType: 'Suspicious activity',
            description: 'This indicator requires further investigation.',
            recommendations: ['Block at firewall', 'Monitor for related activity'],
            ttps: [],
            relatedIndicators: [],
        });
    }
    if (prompt.includes('malware-classification')) {
        return JSON.stringify({
            family: 'Unknown',
            variant: null,
            confidence: 0.5,
            behaviors: ['Network communication'],
            capabilities: ['Data exfiltration potential'],
            associatedActors: [],
        });
    }
    if (prompt.includes('risk-score')) {
        return JSON.stringify({
            score: 50,
            factors: [
                { name: 'Unknown origin', impact: 30, description: 'Source cannot be verified' },
                { name: 'Type risk', impact: 20, description: 'IOC type has moderate inherent risk' },
            ],
            mitigations: ['Add to monitoring', 'Investigate source'],
        });
    }
    if (prompt.includes('CVE ID:') || prompt.includes('vulnerability analyst')) {
        return JSON.stringify({
            exploitabilityScore: 6.5,
            priorityLevel: 'high',
            attackVector: 'network',
            attackComplexity: 'low',
            impactAnalysis: 'This vulnerability could allow remote code execution if successfully exploited. Attackers may gain full control of affected systems.',
            affectedSystems: ['Web servers', 'Application servers', 'Enterprise applications'],
            remediationSteps: [
                'Apply vendor patches immediately',
                'Implement network segmentation',
                'Enable enhanced logging and monitoring'
            ],
            workarounds: ['Disable affected features if possible', 'Implement WAF rules to block exploit attempts'],
            relatedVulnerabilities: [],
            threatActors: [],
        });
    }
    if (prompt.includes('Threat Actor Name:') || prompt.includes('threat actor attribution')) {
        return JSON.stringify({
            threatLevel: 'high',
            operationalSummary: 'This threat actor conducts sophisticated cyber operations targeting critical infrastructure and high-value organizations.',
            primaryTargets: ['Government agencies', 'Critical infrastructure', 'Technology companies'],
            ttpsUsed: ['T1566 - Phishing', 'T1059 - Command and Scripting Interpreter', 'T1078 - Valid Accounts'],
            knownCampaigns: ['Operation Example 2024'],
            attributionConfidence: 0.75,
            defenseRecommendations: [
                'Implement advanced email filtering',
                'Enable MFA on all accounts',
                'Deploy EDR solutions with behavioral analysis',
                'Conduct regular security awareness training'
            ],
            indicatorsToWatch: ['Spear-phishing emails', 'Unusual authentication patterns', 'Lateral movement attempts'],
            relatedActors: [],
        });
    }
    return 'Analysis complete. Further investigation recommended.';
}
