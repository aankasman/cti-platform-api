/**
 * AI Middleware — Unified LLM Interface — Barrel
 *
 * Sub-modules:
 *   - aiMiddleware/types.ts     → Type definitions
 *   - aiMiddleware/registry.ts  → Provider registry & selection
 *   - aiMiddleware/providers.ts → Gemini, OpenRouter, Ollama implementations
 *   - aiMiddleware/callLLM.ts   → Core LLM router with fallback
 *   - aiMiddleware/helpers.ts   → Convenience functions (summarize, extract, classify)
 */

export type { LLMProvider, LLMOptions, LLMResponse, ProviderConfig } from './aiMiddleware/types';
export { getProviders, selectProvider } from './aiMiddleware/registry';
export { callLLM } from './aiMiddleware/callLLM';
export { summarizeContent, extractEntities, classifyThreat } from './aiMiddleware/helpers';

// Status & Info
import { getProviders, selectProvider } from './aiMiddleware/registry';

export function getProviderStatus(): {
    providers: { name: string; available: boolean; model: string }[];
    activeProvider: string;
} {
    const providers = getProviders();
    const active = selectProvider();

    return {
        providers: Object.values(providers).map(p => ({
            name: p.name,
            available: p.available,
            model: p.defaultModel,
        })),
        activeProvider: active.name,
    };
}
