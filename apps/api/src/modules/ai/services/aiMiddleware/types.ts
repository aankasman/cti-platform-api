/**
 * AI Middleware — Types
 */

export type LLMProvider = 'gemini' | 'openrouter' | 'ollama';

export interface LLMOptions {
    provider?: LLMProvider;
    model?: string;
    temperature?: number;
    maxTokens?: number;
    jsonMode?: boolean;
    systemPrompt?: string;
}

export interface LLMResponse {
    text: string;
    provider: LLMProvider;
    model: string;
    tokensUsed?: number;
    latencyMs: number;
}

export interface ProviderConfig {
    name: LLMProvider;
    available: boolean;
    endpoint: string;
    apiKey?: string;
    defaultModel: string;
}
