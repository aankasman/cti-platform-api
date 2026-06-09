/**
 * Automated Drizzle Migration Runner
 *
 * Runs Drizzle-kit migrations programmatically at application startup
 * or via CLI / admin endpoint. Supports:
 *   - Auto-migrate on boot (when ENABLE_AUTO_MIGRATE=true)
 *   - Migration status reporting
 *   - Rollback to a specific version
 *   - Migration history tracking
 *
 * Uses sql.raw() to wrap raw SQL strings for Drizzle compatibility.
 */

import { db, sql, rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('Migrations');

// ============================================================================
// Types
// ============================================================================

export interface MigrationRecord {
    id: number;
    name: string;
    hash: string;
    appliedAt: string;
    executionTimeMs: number;
    status: 'applied' | 'rolled_back' | 'failed';
}

export interface MigrationStatus {
    currentVersion: string | null;
    pendingCount: number;
    appliedCount: number;
    lastAppliedAt: string | null;
    history: MigrationRecord[];
}

// ============================================================================
// Bootstrap — Ensure migration tracking table exists
// ============================================================================

const MIGRATION_TABLE = '__drizzle_migrations';

async function ensureMigrationTable(): Promise<void> {
    try {
        await db.execute(sql`
            CREATE TABLE IF NOT EXISTS __drizzle_migrations (
                id              SERIAL PRIMARY KEY,
                name            TEXT NOT NULL UNIQUE,
                hash            TEXT NOT NULL,
                applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                execution_time_ms INTEGER NOT NULL DEFAULT 0,
                status          TEXT NOT NULL DEFAULT 'applied'
            )
        `);
    } catch (err) {
        // If the table (or its implicit SERIAL sequence type) already exists,
        // Postgres may throw a pg_type duplicate key error — safe to ignore
        const msg = (err as Error).message || '';
        if (!msg.includes('pg_type_typname_nsp_index') && !msg.includes('already exists')) {
            throw err;
        }
        log.debug('Migration table already exists, skipping creation');
    }
}

// ============================================================================
// Core Migration Runner
// ============================================================================

/**
 * Run pending migrations from the drizzle output directory.
 * Reads SQL files from `packages/db/drizzle/` and applies them in order.
 */
export async function runMigrations(): Promise<{
    applied: string[];
    skipped: string[];
    errors: Array<{ name: string; error: string }>;
}> {
    await ensureMigrationTable();

    const applied: string[] = [];
    const skipped: string[] = [];
    const errors: Array<{ name: string; error: string }> = [];

    try {
        // Get list of already-applied migrations.
        //
        // Cross-reference both tracking tables: this runner tracks via
        // `__drizzle_migrations`, but `packages/db/src/scripts/apply-migrations.ts`
        // (the CLI fallback used during emergency manual deploys) tracks via
        // `__sql_migrations`. A name in EITHER counts as applied — that way a
        // manual `db:apply` run doesn't get re-attempted on the next boot,
        // and a future flip to ENABLE_AUTO_MIGRATE=true on a database where
        // some migrations were applied via the CLI runs cleanly.
        //
        // Migration filenames live with the `.sql` suffix in __sql_migrations
        // and without it in __drizzle_migrations. Normalise to the no-suffix
        // form (matching this runner's convention) before union-ing.
        const appliedResult = await db.execute(sql`
            SELECT name FROM __drizzle_migrations WHERE status = 'applied' ORDER BY id
        `) as unknown as RawQueryResult;
        const appliedSet = new Set<string>(
            (appliedResult.rows || []).map((r) => String(r.name))
        );
        try {
            const cliResult = await db.execute(sql`
                SELECT name FROM __sql_migrations
            `) as unknown as RawQueryResult;
            for (const r of cliResult.rows || []) {
                appliedSet.add(String(r.name).replace(/\.sql$/, ''));
            }
        } catch {
            // Table doesn't exist yet — fine, this DB has never run the CLI script.
        }

        // Read migration files from the drizzle output directory
        const fs = await import('fs');
        const path = await import('path');
        const migrationsDir = path.resolve(
            process.env.MIGRATIONS_DIR || 'packages/db/drizzle'
        );

        if (!fs.existsSync(migrationsDir)) {
            log.info('No migrations directory found', { dir: migrationsDir });
            return { applied, skipped, errors };
        }

        const files = fs.readdirSync(migrationsDir)
            .filter((f: string) => f.endsWith('.sql'))
            .sort();

        for (const file of files) {
            const migrationName = file.replace('.sql', '');

            if (appliedSet.has(migrationName)) {
                skipped.push(migrationName);
                continue;
            }

            const sqlContent = fs.readFileSync(
                path.join(migrationsDir, file), 'utf-8'
            );

            // Compute a simple hash for change detection
            const hash = await computeHash(sqlContent);

            const startTime = Date.now();
            try {
                // Execute migration within a transaction
                await db.execute(sql`BEGIN`);
                await db.execute(sql.raw(sqlContent));

                // Record the migration
                const execTime = Date.now() - startTime;
                await db.execute(sql.raw(
                    `INSERT INTO __drizzle_migrations (name, hash, execution_time_ms, status)
                     VALUES ('${migrationName}', '${hash}', ${execTime}, 'applied')`
                ));

                await db.execute(sql`COMMIT`);
                applied.push(migrationName);
                log.info(`Migration applied: ${migrationName}`, {
                    executionTimeMs: Date.now() - startTime,
                });
            } catch (err) {
                await db.execute(sql`ROLLBACK`);
                const errorMsg = formatPgError(err);
                errors.push({ name: migrationName, error: errorMsg });
                log.error(`Migration failed: ${migrationName}`, { error: errorMsg });

                // Record the failed migration
                const execTime = Date.now() - startTime;
                await db.execute(sql.raw(
                    `INSERT INTO __drizzle_migrations (name, hash, execution_time_ms, status)
                     VALUES ('${migrationName}', '${hash}', ${execTime}, 'failed')
                     ON CONFLICT (name) DO UPDATE SET status = 'failed'`
                ));

                // Stop on first failure
                break;
            }
        }
    } catch (err) {
        log.error('Migration runner failed', { error: formatPgError(err) });
        errors.push({ name: '_runner', error: (err as Error).message });
    }

    log.info('Migration run complete', {
        applied: applied.length,
        skipped: skipped.length,
        errors: errors.length,
    });

    return { applied, skipped, errors };
}

// ============================================================================
// Status & History
// ============================================================================

/**
 * Get current migration status and history
 */
export async function getMigrationStatus(): Promise<MigrationStatus> {
    await ensureMigrationTable();

    const result = await db.execute(sql`
        SELECT id, name, hash,
               applied_at::text as applied_at,
               execution_time_ms,
               status
        FROM __drizzle_migrations
        ORDER BY id DESC
    `) as unknown as RawQueryResult;

    const history: MigrationRecord[] = (result.rows || []).map((r) => ({
        id: Number(r.id),
        name: String(r.name),
        hash: String(r.hash),
        appliedAt: String(r.applied_at),
        executionTimeMs: Number(r.execution_time_ms),
        status: String(r.status) as MigrationRecord['status'],
    }));

    const appliedMigrations = history.filter(h => h.status === 'applied');

    // Count pending migrations
    let pendingCount = 0;
    try {
        const fs = await import('fs');
        const path = await import('path');
        const migrationsDir = path.resolve(
            process.env.MIGRATIONS_DIR || 'packages/db/drizzle'
        );
        if (fs.existsSync(migrationsDir)) {
            const files = fs.readdirSync(migrationsDir).filter((f: string) => f.endsWith('.sql'));
            const appliedNames = new Set(appliedMigrations.map(h => h.name));
            pendingCount = files.filter((f: string) => !appliedNames.has(f.replace('.sql', ''))).length;
        }
    } catch {
        // ignore
    }

    return {
        currentVersion: appliedMigrations[0]?.name || null,
        pendingCount,
        appliedCount: appliedMigrations.length,
        lastAppliedAt: appliedMigrations[0]?.appliedAt || null,
        history,
    };
}

/**
 * Rollback the last N applied migrations
 */
export async function rollbackMigrations(count: number = 1): Promise<{
    rolledBack: string[];
    errors: Array<{ name: string; error: string }>;
}> {
    await ensureMigrationTable();

    const rolledBack: string[] = [];
    const errors: Array<{ name: string; error: string }> = [];

    const result = await rawQuery(`
        SELECT name, hash
        FROM __drizzle_migrations
        WHERE status = 'applied'
        ORDER BY id DESC
        LIMIT ${count}
    `);

    const toRollback = result.rows as Array<{ name: string; hash: string }>;

    for (const migration of toRollback) {
        try {
            await db.execute(sql.raw(
                `UPDATE __drizzle_migrations
                 SET status = 'rolled_back'
                 WHERE name = '${migration.name}'`
            ));
            rolledBack.push(migration.name);
            log.info(`Migration rolled back: ${migration.name}`);
        } catch (err) {
            errors.push({ name: migration.name, error: (err as Error).message });
            log.error(`Rollback failed: ${migration.name}`, { error: (err as Error).message });
        }
    }

    return { rolledBack, errors };
}

// ============================================================================
// Auto-Migrate Hook
// ============================================================================

/**
 * Run migrations on startup if ENABLE_AUTO_MIGRATE=true
 */
export async function autoMigrateOnStartup(): Promise<void> {
    if (process.env.ENABLE_AUTO_MIGRATE !== 'true') {
        log.info('Auto-migrate disabled (set ENABLE_AUTO_MIGRATE=true to enable)');
        return;
    }

    log.info('Auto-migrate enabled — running pending migrations...');
    const result = await runMigrations();

    if (result.errors.length > 0) {
        log.error('Auto-migrate completed with errors', {
            applied: result.applied.length,
            errors: result.errors,
        });
    } else {
        log.info('Auto-migrate complete', {
            applied: result.applied.length,
            skipped: result.skipped.length,
        });
    }
}

// ============================================================================
// Helper
// ============================================================================

async function computeHash(content: string): Promise<string> {
    const crypto = await import('crypto');
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

/**
 * Extract a useful diagnostic string from whatever the database driver
 * threw. postgres-js errors aren't `Error` instances — they're plain
 * objects with `.code` (e.g. '42P07'), `.detail`, `.hint`, `.position`,
 * `.where`, `.message_primary`. Until 2026-06-09 the runner did
 * `(err as Error).message` which logged literal `[object Object]`
 * for those payloads, hiding the real reason.
 *
 * Format we want: `<code> <message> | detail=<…> | hint=<…>` — short
 * enough to grep, structured enough to act on.
 */
function formatPgError(err: unknown): string {
    if (err == null) return 'unknown error';
    if (typeof err === 'string') return err;
    const e = err as {
        code?: string; message?: string; detail?: string; hint?: string;
        where?: string; severity?: string; routine?: string;
        message_primary?: string;
    };
    const parts: string[] = [];
    if (e.code) parts.push(e.code);
    const msg = e.message_primary ?? e.message;
    if (msg) parts.push(typeof msg === 'string' ? msg : String(msg));
    if (e.detail) parts.push(`detail=${e.detail}`);
    if (e.hint) parts.push(`hint=${e.hint}`);
    if (e.where) parts.push(`where=${e.where}`);
    if (parts.length > 0) return parts.join(' | ');
    // Last-ditch fallback so we never log raw [object Object].
    try { return JSON.stringify(err); } catch { return String(err); }
}
