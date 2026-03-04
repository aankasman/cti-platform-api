/**
 * Notification Service
 * 
 * Handles sending notifications via Email and Slack for threat intelligence alerts.
 */

import { db, sql, notifications as notificationsTable, desc, eq, count } from '@rinjani/db';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Notifications');

// ============================================================================
// In-App Notification CRUD (dashboard bell)
// ============================================================================

/** Insert an in-app notification visible in the dashboard bell. */
export async function createInAppNotification(data: {
    type?: string;
    title: string;
    message: string;
    source?: string;
    metadata?: Record<string, unknown>;
}) {
    const [row] = await db.insert(notificationsTable).values({
        type: data.type ?? 'info',
        title: data.title,
        message: data.message,
        source: data.source ?? 'system',
        metadata: data.metadata ?? {},
    }).returning();
    log.info('In-app notification created', { id: row.id, title: row.title });
    return row;
}

/** List recent in-app notifications, newest first. */
export async function getInAppNotifications(limit = 50, offset = 0) {
    const rows = await db.select()
        .from(notificationsTable)
        .orderBy(desc(notificationsTable.createdAt))
        .limit(limit)
        .offset(offset);
    return rows;
}

/** Return number of unread in-app notifications. */
export async function getUnreadCount(): Promise<number> {
    const [row] = await db.select({ c: count() })
        .from(notificationsTable)
        .where(eq(notificationsTable.read, false));
    return row?.c ?? 0;
}

/** Mark one or all notifications as read. */
export async function markNotificationsRead(id?: string) {
    if (id) {
        await db.update(notificationsTable)
            .set({ read: true })
            .where(eq(notificationsTable.id, id));
    } else {
        await db.update(notificationsTable)
            .set({ read: true })
            .where(eq(notificationsTable.read, false));
    }
}

// Types
export interface NotificationConfig {
    id: string;
    userId: string;
    emailEnabled: boolean;
    emailAddress: string | null;
    slackEnabled: boolean;
    slackWebhookUrl: string | null;
    severityThreshold: 'critical' | 'high' | 'medium' | 'low';
    notifyOnNewIOC: boolean;
    notifyOnNewVuln: boolean;
    notifyOnThreatActor: boolean;
    createdAt: string;
    updatedAt: string;
}

export interface NotificationPayload {
    type: 'ioc' | 'vulnerability' | 'threat_actor' | 'alert';
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    message: string;
    data?: Record<string, unknown>;
}

// Severity priority for filtering
const SEVERITY_PRIORITY: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
};

/**
 * Send notification to Slack webhook
 */
export async function sendSlackNotification(
    webhookUrl: string,
    payload: NotificationPayload
): Promise<{ success: boolean; error?: string }> {
    try {
        const color = {
            critical: '#ef4444',
            high: '#f59e0b',
            medium: '#3b82f6',
            low: '#10b981',
        }[payload.severity] || '#6b7280';

        const slackPayload = {
            attachments: [{
                color,
                title: `🔔 ${payload.title}`,
                text: payload.message,
                fields: [
                    { title: 'Type', value: payload.type.toUpperCase(), short: true },
                    { title: 'Severity', value: payload.severity.toUpperCase(), short: true },
                ],
                footer: 'Rinjani CTI Platform',
                ts: Math.floor(Date.now() / 1000),
            }],
        };

        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(slackPayload),
        });

        if (!response.ok) {
            return { success: false, error: `Slack API error: ${response.status}` };
        }

        return { success: true };
    } catch (error) {
        return { success: false, error: (error as Error).message };
    }
}

/**
 * Send notification via email using Nodemailer/SMTP.
 * Lazy-initializes SMTP transport from environment variables.
 * Falls back to log-only if SMTP is not configured.
 */

let smtpTransport: import('nodemailer').Transporter | null | undefined = undefined; // lazy-init

async function getSmtpTransport() {
    if (smtpTransport !== undefined) return smtpTransport;

    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '587', 10);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    if (!host) {
        log.info('SMTP not configured (SMTP_HOST missing) — email notifications will be logged only');
        smtpTransport = null;
        return null;
    }

    try {
        const nodemailer = await import('nodemailer');
        smtpTransport = nodemailer.createTransport({
            host,
            port,
            secure: port === 465,
            auth: user && pass ? { user, pass } : undefined,
        });

        // Verify connection
        await smtpTransport.verify();
        log.info('SMTP transport initialized', { host, port });
    } catch (err) {
        log.warn('SMTP transport init failed, falling back to log-only', { error: (err as Error).message });
        smtpTransport = null;
    }

    return smtpTransport;
}

export async function sendEmailNotification(
    emailAddress: string,
    payload: NotificationPayload
): Promise<{ success: boolean; error?: string }> {
    try {
        const transport = await getSmtpTransport();
        const subject = `[${payload.severity.toUpperCase()}] ${payload.title}`;

        if (!transport) {
            // Log-only fallback when SMTP is not configured
            log.info('Email notification (logged)', { to: emailAddress, subject });
            return { success: true };
        }

        const severityColor = {
            critical: '#ef4444',
            high: '#f59e0b',
            medium: '#3b82f6',
            low: '#10b981',
        }[payload.severity] || '#6b7280';

        const html = `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: ${severityColor}; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
                    <h2 style="margin: 0; font-size: 18px;">🔔 ${payload.title}</h2>
                </div>
                <div style="background: #1a1a2e; color: #e0e0e0; padding: 24px; border-radius: 0 0 8px 8px;">
                    <p style="margin: 0 0 16px;">${payload.message}</p>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #333; color: #888;">Type</td>
                            <td style="padding: 8px; border-bottom: 1px solid #333;">${payload.type.toUpperCase()}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #333; color: #888;">Severity</td>
                            <td style="padding: 8px; border-bottom: 1px solid #333; color: ${severityColor}; font-weight: bold;">${payload.severity.toUpperCase()}</td>
                        </tr>
                    </table>
                    <p style="margin: 24px 0 0; font-size: 12px; color: #666;">Rinjani CTI Platform • ${new Date().toISOString()}</p>
                </div>
            </div>
        `;

        const fromAddr = process.env.SMTP_FROM || 'alerts@rinjani.io';

        await transport.sendMail({
            from: `"Rinjani CTI" <${fromAddr}>`,
            to: emailAddress,
            subject,
            text: `${payload.title}\n\n${payload.message}\n\nType: ${payload.type}\nSeverity: ${payload.severity}`,
            html,
        });

        log.info('Email sent', { to: emailAddress, subject });
        return { success: true };
    } catch (error) {
        log.warn('Email send failed', { to: emailAddress, error: (error as Error).message });
        return { success: false, error: (error as Error).message };
    }
}


/**
 * Check if notification should be sent based on config
 */
export function shouldNotify(
    config: NotificationConfig,
    payload: NotificationPayload
): boolean {
    // Check severity threshold
    const configPriority = SEVERITY_PRIORITY[config.severityThreshold] || 0;
    const payloadPriority = SEVERITY_PRIORITY[payload.severity] || 0;

    if (payloadPriority < configPriority) {
        return false;
    }

    // Check notification type preference
    switch (payload.type) {
        case 'ioc':
            return config.notifyOnNewIOC;
        case 'vulnerability':
            return config.notifyOnNewVuln;
        case 'threat_actor':
            return config.notifyOnThreatActor;
        case 'alert':
            return true; // Always notify on general alerts
        default:
            return false;
    }
}

/**
 * Send notifications to all configured recipients
 */
export async function broadcastNotification(
    payload: NotificationPayload
): Promise<{ sent: number; failed: number; errors: string[] }> {
    const results = { sent: 0, failed: 0, errors: [] as string[] };

    try {
        // Get all notification configs
        const configs = await db.execute(sql`
            SELECT * FROM notification_configs WHERE 
                (email_enabled = true AND email_address IS NOT NULL)
                OR (slack_enabled = true AND slack_webhook_url IS NOT NULL)
        `) as unknown as NotificationConfig[];

        for (const config of configs) {
            if (!shouldNotify(config, payload)) {
                continue;
            }

            // Send Slack notification
            if (config.slackEnabled && config.slackWebhookUrl) {
                const slackResult = await sendSlackNotification(config.slackWebhookUrl, payload);
                if (slackResult.success) {
                    results.sent++;
                } else {
                    results.failed++;
                    results.errors.push(`Slack: ${slackResult.error}`);
                }
            }

            // Send Email notification
            if (config.emailEnabled && config.emailAddress) {
                const emailResult = await sendEmailNotification(config.emailAddress, payload);
                if (emailResult.success) {
                    results.sent++;
                } else {
                    results.failed++;
                    results.errors.push(`Email: ${emailResult.error}`);
                }
            }
        }
    } catch (error) {
        results.errors.push(`Broadcast error: ${(error as Error).message}`);
    }

    return results;
}

/**
 * Create a high-severity alert notification
 */
export function createAlertPayload(
    type: 'ioc' | 'vulnerability' | 'threat_actor',
    severity: 'critical' | 'high' | 'medium' | 'low',
    details: { value?: string; cveId?: string; name?: string }
): NotificationPayload {
    let title = '';
    let message = '';

    switch (type) {
        case 'ioc':
            title = `New ${severity} IOC Detected`;
            message = `A new ${severity}-severity indicator was detected: ${details.value || 'Unknown'}`;
            break;
        case 'vulnerability':
            title = `New ${severity} Vulnerability`;
            message = `A ${severity}-severity vulnerability was added: ${details.cveId || 'Unknown'}`;
            break;
        case 'threat_actor':
            title = `Threat Actor Activity`;
            message = `New activity detected for threat actor: ${details.name || 'Unknown'}`;
            break;
    }

    return { type, severity, title, message, data: details };
}
