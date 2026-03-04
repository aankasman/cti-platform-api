/**
 * Shared helpers for v1 sub-routes.
 */

// Helper for pagination
export function paginate(page: number, pageSize: number, total: number) {
    return {
        page,
        pageSize,
        totalItems: total,
        totalPages: Math.ceil(total / pageSize),
    };
}
