/**
 * Threat Intel Service
 */

import { db } from '@rinjani/db';
import { threatActors } from '@rinjani/db/schema';
import { eq, like, desc } from 'drizzle-orm';
import type { ServiceContext, ServiceResult, PaginatedResult, ThreatActor, PaginationParams } from '../types';

export const threatIntelService = {
    async list(ctx: ServiceContext, params: PaginationParams = {}): Promise<ServiceResult<PaginatedResult<ThreatActor>>> {
        const page = params.page || 1;
        const pageSize = params.pageSize || 25;
        const offset = (page - 1) * pageSize;

        const results = await db.select()
            .from(threatActors)
            .orderBy(desc(threatActors.createdAt))
            .limit(pageSize)
            .offset(offset);

        const countResult = await db.select().from(threatActors);
        const totalItems = countResult.length;
        const totalPages = Math.ceil(totalItems / pageSize);

        return {
            success: true,
            data: {
                items: results.map(mapThreatActor),
                pagination: {
                    page,
                    pageSize,
                    totalItems,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1,
                },
            },
        };
    },

    async findById(ctx: ServiceContext, id: string): Promise<ServiceResult<ThreatActor>> {
        const results = await db.select()
            .from(threatActors)
            .where(eq(threatActors.id, id))
            .limit(1);

        if (results.length === 0) {
            return {
                success: false,
                error: { code: 'NOT_FOUND', message: 'Threat actor not found' },
            };
        }

        return {
            success: true,
            data: mapThreatActor(results[0]),
        };
    },

    async search(ctx: ServiceContext, query: string): Promise<ServiceResult<ThreatActor[]>> {
        const results = await db.select()
            .from(threatActors)
            .where(like(threatActors.name, `%${query}%`))
            .limit(50);

        return {
            success: true,
            data: results.map(mapThreatActor),
        };
    },
};

function mapThreatActor(row: typeof threatActors.$inferSelect): ThreatActor {
    return {
        id: row.id,
        stixId: row.stixId,
        name: row.name,
        description: row.description || undefined,
        aliases: (row.aliases as string[]) || [],
        sophistication: row.sophistication || undefined,
        resourceLevel: row.resourceLevel || undefined,
        primaryMotivation: row.primaryMotivation || undefined,
        labels: (row.labels as string[]) || [],
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
    };
}
