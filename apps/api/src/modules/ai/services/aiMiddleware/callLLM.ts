/**
 * AI Middleware — Core LLM Router
 */

import { createLogger } from '../../../../lib/logger';
import type { LLMOptions, LLMResponse } from './types';
import { selectProvider, getProviders } from './registry';
import { callGemini, callOpenRouter, callOllama } from './providers';

const log = createLogger('AI:MW');

/**
 * Unified LLM call. Routes to appropriate provider automatically.
 */
export async function callLLM(prompt: string, opts: LLMOptions = {}): Promise<LLMResponse> {
    const provider = selectProvider(opts.provider);
    const model = opts.model || provider.defaultModel;
    const start = Date.now();

    log.info('LLM call', { provider: provider.name, model, promptPreview: prompt.slice(0, 80) });

    try {
        switch (provider.name) {
            case 'gemini':
                return await callGemini(provider, model, prompt, opts, start);
            case 'openrouter':
                return await callOpenRouter(provider, model, prompt, opts, start);
            case 'ollama':
                return await callOllama(provider, model, prompt, opts, start);
            default:
                throw new Error(`Unknown provider: ${provider.name}`);
        }
    } catch (err) {
        // Try fallback if preferred provider fails
        if (opts.provider) {
            log.warn('Provider failed, trying fallback', { provider: provider.name, error: (err as Error).message });
            return callLLM(prompt, { ...opts, provider: undefined });
        }

        // Try OpenRouter as last resort before Ollama
        if (provider.name === 'gemini' && getProviders().openrouter.available) {
            log.warn('Gemini failed, falling back to OpenRouter');
            return callLLM(prompt, { ...opts, provider: 'openrouter' });
        }

        throw err;
    }
}
