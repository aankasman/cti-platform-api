/**
 * Web Intelligence Persistence — Types
 */

export interface ScrapeData {
    url: string;
    title?: string;
    text?: string;
    summary?: string;
    aiSummary?: string;
    entities?: Record<string, string[]>;
    iocs?: Record<string, string[]>;
    iocStats?: Record<string, number>;
    engines?: string[];
    fetchedAt?: string;
    status?: Record<string, string>;
}

export interface SaveResult {
    itemId: string;
    isNew: boolean;
    mentionsCreated: number;
}
