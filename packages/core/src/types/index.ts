/**
 * Core Types
 */

export interface ServiceContext {
    requestId: string;
    userId?: string;
    organizationId?: string;
    permissions: string[];
    traceId?: string;
}

export interface ServiceResult<T> {
    success: boolean;
    data?: T;
    error?: {
        code: string;
        message: string;
    };
}

export interface PaginationParams {
    page?: number;
    pageSize?: number;
}

export interface PaginatedResult<T> {
    items: T[];
    pagination: {
        page: number;
        pageSize: number;
        totalItems: number;
        totalPages: number;
        hasNext: boolean;
        hasPrev: boolean;
    };
}

export interface ThreatActor {
    id: string;
    stixId: string;
    name: string;
    description?: string;
    aliases: string[];
    sophistication?: string;
    resourceLevel?: string;
    primaryMotivation?: string;
    labels: string[];
    createdAt: Date;
    updatedAt: Date;
}

export interface Indicator {
    id: string;
    stixId: string;
    pattern: string;
    patternType: string;
    name?: string;
    description?: string;
    validFrom?: Date;
    validUntil?: Date;
    labels: string[];
}
