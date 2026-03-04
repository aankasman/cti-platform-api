/**
 * PostgreSQL NOTIFY/LISTEN for Real-Time OpenSearch Sync
 * 
 * Listens for database trigger notifications and indexes records to OpenSearch.
 */

import pg from 'pg';
import { db, eq } from '@rinjani/db';
import { iocs, vulnerabilities, threatActors } from '@rinjani/db/schema';
import {
    indexSingleIOC,
    indexSingleVulnerability,
    indexSingleActor
} from './opensearch';
import { createLogger } from '../lib/logger';

const log = createLogger('DBListener');

const { Client } = pg;

// Configuration
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/rinjani_v3';
const RECONNECT_DELAY_MS = 5000;

// Listener state
let client: pg.Client | null = null;
let isListening = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;

// Stats tracking
let stats = {
    iocsIndexed: 0,
    vulnerabilitiesIndexed: 0,
    actorsIndexed: 0,
    errors: 0,
    lastNotification: null as Date | null,
};

/**
 * Handle incoming notification
 */
async function handleNotification(payload: string) {
    try {
        const data = JSON.parse(payload);
        const { table, operation, id } = data;

        stats.lastNotification = new Date();

        switch (table) {
            case 'iocs': {
                const [record] = await db.select().from(iocs).where(eq(iocs.id, id)).limit(1);
                if (record) {
                    await indexSingleIOC(record);
                    stats.iocsIndexed++;
                }
                break;
            }
            case 'vulnerabilities': {
                const [record] = await db.select().from(vulnerabilities).where(eq(vulnerabilities.id, id)).limit(1);
                if (record) {
                    await indexSingleVulnerability(record);
                    stats.vulnerabilitiesIndexed++;
                }
                break;
            }
            case 'threat_actors': {
                const [record] = await db.select().from(threatActors).where(eq(threatActors.id, id)).limit(1);
                if (record) {
                    await indexSingleActor(record);
                    stats.actorsIndexed++;
                }
                break;
            }
            default:
                log.warn('Unknown table in notification', { table });
        }
    } catch (error) {
        stats.errors++;
        log.error('Error processing notification', error as Error);
    }
}

/**
 * Start listening for PostgreSQL notifications
 */
export async function startDBListener(): Promise<void> {
    if (isListening) {
        log.info('Already listening');
        return;
    }

    try {
        client = new Client({ connectionString: DATABASE_URL });

        client.on('notification', (msg: pg.Notification) => {
            if (msg.channel === 'opensearch_sync' && msg.payload) {
                handleNotification(msg.payload);
            }
        });

        client.on('error', (err: Error) => {
            log.error('Connection error', new Error(err.message));
            isListening = false;
            scheduleReconnect();
        });

        client.on('end', () => {
            log.info('Connection closed');
            isListening = false;
        });

        await client.connect();
        await client.query('LISTEN opensearch_sync');

        isListening = true;
        reconnectAttempts = 0;
        log.info('Listening for OpenSearch sync notifications');

    } catch (error) {
        log.error('Failed to start', new Error((error as Error).message));
        scheduleReconnect();
    }
}

/**
 * Schedule reconnection attempt
 */
function scheduleReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        log.error('Max reconnection attempts reached');
        return;
    }

    reconnectAttempts++;
    const delay = RECONNECT_DELAY_MS * Math.min(reconnectAttempts, 6); // Cap at 30s

    log.info('Reconnecting', { delaySec: delay / 1000, attempt: reconnectAttempts, maxAttempts: MAX_RECONNECT_ATTEMPTS });

    setTimeout(() => {
        startDBListener();
    }, delay);
}

/**
 * Stop listening
 */
export async function stopDBListener(): Promise<void> {
    if (client) {
        try {
            await client.query('UNLISTEN opensearch_sync');
            await client.end();
        } catch (error) {
            // Ignore errors on shutdown
        }
        client = null;
        isListening = false;
        log.info('Stopped');
    }
}

/**
 * Get listener stats
 */
export function getDBListenerStats() {
    return {
        isListening,
        reconnectAttempts,
        ...stats,
    };
}
