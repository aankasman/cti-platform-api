/**
 * AI Middleware — Provider Implementations
 */

import type { LLMOptions, LLMResponse, ProviderConfig } from './types';

export async function callGemini(
    provider: ProviderConfig, model: string, prompt: string, opts: LLMOptions, start: number,
): Promise<LLMResponse> {
    const url = `${provider.endpoint}/${model}:generateContent?key=${provider.apiKey}`;

    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                temperature: opts.temperature ?? 0.3,
                maxOutputTokens: opts.maxTokens ?? 4096,
                ...(opts.jsonMode && { responseMimeType: 'application/json' }),
            },
        }),
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Gemini ${res.status}: ${errText.slice(0, 200)}`);
    }

    const data = await res.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const tokensUsed = (data.usageMetadata?.promptTokenCount || 0) +
        (data.usageMetadata?.candidatesTokenCount || 0);

    return { text, provider: 'gemini', model, tokensUsed, latencyMs: Date.now() - start };
}

export async function callOpenRouter(
    provider: ProviderConfig, model: string, prompt: string, opts: LLMOptions, start: number,
): Promise<LLMResponse> {
    const messages: Array<{ role: string; content: string }> = [];

    if (opts.systemPrompt) {
        messages.push({ role: 'system', content: opts.systemPrompt });
    }
    messages.push({ role: 'user', content: prompt });

    const body: Record<string, unknown> = {
        model,
        messages,
        temperature: opts.temperature ?? 0.3,
        max_tokens: opts.maxTokens ?? 4096,
    };

    if (opts.jsonMode) {
        body.response_format = { type: 'json_object' };
    }

    const res = await fetch(provider.endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${provider.apiKey}`,
            'HTTP-Referer': 'https://rinjani.ai',
            'X-Title': 'RinjaniCTI',
        },
        body: JSON.stringify(body),
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`OpenRouter ${res.status}: ${errText.slice(0, 200)}`);
    }

    const data = await res.json();
    const text = data.choices?.[0]?.message?.content || '';
    const tokensUsed = data.usage?.total_tokens || 0;

    return { text, provider: 'openrouter', model, tokensUsed, latencyMs: Date.now() - start };
}

export async function callOllama(
    provider: ProviderConfig, model: string, prompt: string, opts: LLMOptions, start: number,
): Promise<LLMResponse> {
    const body: Record<string, unknown> = {
        model,
        prompt,
        stream: false,
        options: {
            temperature: opts.temperature ?? 0.3,
            num_predict: opts.maxTokens ?? 4096,
        },
    };

    if (opts.jsonMode) {
        body.format = 'json';
    }

    if (opts.systemPrompt) {
        body.system = opts.systemPrompt;
    }

    const res = await fetch(provider.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60000),
    });

    if (!res.ok) {
        throw new Error(`Ollama ${res.status}`);
    }

    const data = await res.json();
    return {
        text: data.response || '',
        provider: 'ollama',
        model,
        latencyMs: Date.now() - start,
    };
}
