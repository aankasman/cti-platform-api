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
 * Call Ollama (local) API.
 *
 * Errors propagate to the caller — historically this function caught
 * connection failures and returned a fabricated `getMockResponse()`
 * payload (a hard-coded "medium severity / 0.7 confidence" threat
 * assessment, etc.) so the UI always rendered SOMETHING. That payload
 * looked like real analysis but wasn't — analysts had no way to tell
 * the AI was unavailable, and the mock data could influence triage
 * decisions on indicators it never actually saw.
 *
 * Both call sites in `analysis.ts` wrap this in a try/catch and
 * return `{ success: false, error }`, which surfaces honestly to the
 * client as "AI provider unreachable" — the right outcome.
 */
export async function callOllama(provider: AIProviderConfig, prompt: string): Promise<{ response: string }> {
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
}
