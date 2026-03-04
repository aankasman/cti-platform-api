/**
 * Nexus Zod Schemas
 *
 * Validation schemas shared across nexus sub-modules.
 */

import { z } from 'zod';

export const SearchSchema = z.object({
    query: z.string().min(1, 'query is required').max(500),
    numResults: z.number().int().min(1).max(25).default(10),
    provider: z.enum(['searxng', 'exa']).default('searxng'),
    categories: z.array(z.string()).optional(),
    timeRange: z.string().optional(),
    type: z.string().optional(),
    includeText: z.boolean().optional(),
});

export const ThreatSearchSchema = z.object({
    query: z.string().min(1, 'query is required').max(500),
    numResults: z.number().int().min(1).max(25).default(10),
    provider: z.enum(['searxng', 'exa']).default('searxng'),
});

export const ScrapeSchema = z.object({
    url: z.string().url('Must be a valid URL'),
    summarize: z.boolean().default(false),
    extractEntities: z.boolean().default(false),
});

export const CreateWebsetSchema = z.object({
    category: z.enum(['malware-c2', 'zero-day-cve', 'apt-actors', 'socmint'], {
        required_error: 'category is required (malware-c2, zero-day-cve, apt-actors, socmint)',
    }),
});

export const ExtractIOCsSchema = z.object({
    text: z.string().min(1, 'text is required'),
});

export const LookupSchema = z.object({
    url: z.string().url('Must be a valid URL'),
});
