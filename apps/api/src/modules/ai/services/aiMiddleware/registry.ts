/**
 * AI Middleware — Provider Registry
 */

import type { LLMProvider, ProviderConfig } from './types';

export function getProviders(): Record<LLMProvider, ProviderConfig> {
    return {
        gemini: {
            name: 'gemini',
            available: !!(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY),
            endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
            apiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY,
            defaultModel: 'gemini-2.0-flash',
        },
        openrouter: {
            name: 'openrouter',
            available: !!process.env.OPENROUTER_API_KEY,
            endpoint: 'https://openrouter.ai/api/v1/chat/completions',
            apiKey: process.env.OPENROUTER_API_KEY,
            defaultModel: 'google/gemini-2.0-flash-001',
        },
        ollama: {
            name: 'ollama',
            available: true,
            endpoint: process.env.OLLAMA_URL || 'http://localhost:11434/api/generate',
            defaultModel: process.env.OLLAMA_MODEL || 'llama3.2',
        },
    };
}

/** Get the best available provider in priority order */
export function selectProvider(preferred?: LLMProvider): ProviderConfig {
    const providers = getProviders();

    if (preferred && providers[preferred]?.available) {
        return providers[preferred];
    }

    // Fallback chain: Gemini → OpenRouter → Ollama
    if (providers.gemini.available) return providers.gemini;
    if (providers.openrouter.available) return providers.openrouter;
    return providers.ollama;
}
