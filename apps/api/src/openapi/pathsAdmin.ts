/**
 * OpenAPI Paths — Admin & System endpoints (Alerts, Notifications, Ops, Users, Queue Admin)
 */

export const pathsAdmin = {
    // Alerts
    '/v1/alerts': {
        get: {
            tags: ['Alerts'],
            summary: 'List alerts',
            description: 'List alerts with pagination and filtering by severity or read status.',
            parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
                { name: 'severity', in: 'query', schema: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] } },
                { name: 'unread', in: 'query', schema: { type: 'string', enum: ['true', 'false'] }, description: 'Filter unread only' },
            ],
            responses: {
                '200': {
                    description: 'Paginated list of alerts',
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            alerts: { type: 'array', items: { $ref: '#/components/schemas/Alert' } },
                                            pagination: { $ref: '#/components/schemas/Pagination' },
                                        }
                                    },
                                }
                            }
                        }
                    },
                },
                '401': { description: 'Unauthorized' },
            },
        },
        post: {
            tags: ['Alerts'],
            summary: 'Create manual alert',
            description: 'Create a new alert manually for testing or system events.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['title', 'message'], properties: {
                                title: { type: 'string', example: 'Test Alert' },
                                message: { type: 'string', example: 'This is a test alert' },
                                severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
                                type: { type: 'string', default: 'system_alert' },
                                metadata: { type: 'object', additionalProperties: true },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': {
                    description: 'Alert queued', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { jobId: { type: 'string' }, severity: { type: 'string' }, title: { type: 'string' }, status: { type: 'string' } } },
                                }
                            }
                        }
                    }
                },
                '400': { description: 'Missing title or message' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/v1/alerts/unread/count': {
        get: {
            tags: ['Alerts'],
            summary: 'Get unread alert count',
            description: 'Get the count of unread alerts for badge display.',
            responses: {
                '200': {
                    description: 'Unread count', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            unread: { type: 'integer', example: 5 },
                                            highSeverity: { type: 'integer', example: 2 },
                                            timestamp: { type: 'string', format: 'date-time' },
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/v1/alerts/{id}/read': {
        post: {
            tags: ['Alerts'],
            summary: 'Mark alert as read',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Alert marked as read' },
                '404': { description: 'Alert not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/v1/alerts/read-all': {
        post: {
            tags: ['Alerts'],
            summary: 'Mark all alerts as read',
            responses: {
                '200': {
                    description: 'All alerts marked as read', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { markedRead: { type: 'integer' } } },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    // Notifications
    '/v1/notifications/settings': {
        get: {
            tags: ['Notifications'],
            summary: 'Get notification settings',
            description: 'Get notification preferences for the current user.',
            responses: {
                '200': {
                    description: 'Notification settings', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { $ref: '#/components/schemas/NotificationSettings' },
                                }
                            }
                        }
                    }
                },
            },
        },
        put: {
            tags: ['Notifications'],
            summary: 'Update notification settings',
            description: 'Update notification preferences (email, Slack, severity threshold).',
            requestBody: {
                required: true,
                content: { 'application/json': { schema: { $ref: '#/components/schemas/NotificationSettings' } } },
            },
            responses: {
                '200': { description: 'Settings updated' },
                '500': { description: 'Server error' },
            },
        },
    },
    '/v1/notifications/test/slack': {
        post: {
            tags: ['Notifications'],
            summary: 'Test Slack webhook',
            description: 'Send a test notification to a Slack webhook URL.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['webhookUrl'], properties: {
                                webhookUrl: { type: 'string', example: 'https://hooks.slack.com/services/...' },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': { description: 'Test result' },
                '400': { description: 'Missing webhookUrl' },
            },
        },
    },
    '/v1/notifications/test/email': {
        post: {
            tags: ['Notifications'],
            summary: 'Test email integration',
            description: 'Send a test notification email.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['emailAddress'], properties: {
                                emailAddress: { type: 'string', format: 'email', example: 'analyst@rinjani.io' },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': { description: 'Test result' },
                '400': { description: 'Missing emailAddress' },
            },
        },
    },
    '/v1/notifications/alert': {
        post: {
            tags: ['Notifications'],
            summary: 'Broadcast manual alert',
            description: 'Manually trigger an alert broadcast to all configured notification channels.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['type', 'severity', 'title', 'message'], properties: {
                                type: { type: 'string', example: 'critical_threat' },
                                severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
                                title: { type: 'string', example: 'APT Group Activity Detected' },
                                message: { type: 'string' },
                                data: { type: 'object', additionalProperties: true },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': {
                    description: 'Broadcast result', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { sent: { type: 'integer' }, failed: { type: 'integer' }, errors: { type: 'array', items: { type: 'string' } } } },
                                }
                            }
                        }
                    }
                },
                '400': { description: 'Missing required fields' },
            },
        },
    },
    '/v1/notifications/history': {
        get: {
            tags: ['Notifications'],
            summary: 'Get notification history',
            description: 'Get recent notification logs.',
            parameters: [
                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
            ],
            responses: {
                '200': {
                    description: 'Notification logs', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { logs: { type: 'array', items: { type: 'object' } }, total: { type: 'integer' } } },
                                }
                            }
                        }
                    }
                },
            },
        },
    },
    // Ops
    '/v1/ops/system': {
        get: {
            tags: ['Ops'],
            summary: 'Infrastructure health',
            description: 'Get health status of PostgreSQL, Redis, OpenSearch, and Neo4j with connection metrics.',
            responses: {
                '200': {
                    description: 'System health', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { $ref: '#/components/schemas/SystemHealth' },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
                '500': { description: 'Health check failed' },
            },
        },
    },
    '/v1/ops/ingestion': {
        get: {
            tags: ['Ops'],
            summary: 'IOC ingestion rates',
            description: 'Get IOC ingestion rates (per hour, per day), feed breakdown, and total counts.',
            responses: {
                '200': {
                    description: 'Ingestion metrics', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            currentRate: { type: 'object', properties: { iocsPerHour: { type: 'integer' }, iocsPerMinute: { type: 'integer' } } },
                                            hourly: { type: 'array', items: { type: 'object', properties: { timestamp: { type: 'string' }, count: { type: 'integer' } } } },
                                            daily: { type: 'array', items: { type: 'object', properties: { date: { type: 'string' }, count: { type: 'integer' } } } },
                                            feedBreakdown: { type: 'array', items: { type: 'object', properties: { feed: { type: 'string' }, itemsProcessed: { type: 'integer' } } } },
                                            totalIOCs: { type: 'integer' },
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
                '500': { description: 'Failed to fetch metrics' },
            },
        },
    },
    '/v1/ops/enrichment': {
        get: {
            tags: ['Ops'],
            summary: 'Enrichment performance',
            description: 'Get enrichment success rates, average processing times, queue status, and recent errors.',
            responses: {
                '200': {
                    description: 'Enrichment metrics', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            queue: { $ref: '#/components/schemas/QueueStats' },
                                            performance: { type: 'object', properties: { successRate: { type: 'integer' }, avgProcessingTimeMs: { type: 'integer' }, totalProcessed: { type: 'integer' } } },
                                            errorBreakdown: { type: 'object', additionalProperties: { type: 'integer' } },
                                            recentErrors: { type: 'array', items: { type: 'object', properties: { jobId: { type: 'string' }, iocValue: { type: 'string' }, error: { type: 'string' }, timestamp: { type: 'string' } } } },
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/v1/ops/workers': {
        get: {
            tags: ['Ops'],
            summary: 'Worker performance metrics',
            description: 'Get throughput, processing times, error rates, and queue depths for all BullMQ workers.',
            responses: {
                '200': {
                    description: 'Worker metrics', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            summary: { type: 'object', properties: { totalActive: { type: 'integer' }, totalWaiting: { type: 'integer' }, totalThroughputPerHour: { type: 'integer' } } },
                                            workers: {
                                                type: 'array', items: {
                                                    type: 'object', properties: {
                                                        name: { type: 'string' },
                                                        counts: { $ref: '#/components/schemas/QueueStats' },
                                                        performance: { type: 'object', properties: { throughputPerHour: { type: 'integer' }, avgProcessingTimeMs: { type: 'integer' }, errorRate: { type: 'integer' } } },
                                                        recentFailures: { type: 'array', items: { type: 'object' } },
                                                    }
                                                }
                                            },
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    // Users
    '/v1/users': {
        get: {
            tags: ['Users'],
            summary: 'List all users',
            description: 'List all users with optional filtering. Admin only.',
            parameters: [
                { name: 'status', in: 'query', schema: { type: 'string', enum: ['all', 'active', 'inactive', 'pending'] } },
                { name: 'role', in: 'query', schema: { type: 'string', enum: ['all', 'admin', 'analyst', 'viewer'] } },
            ],
            responses: {
                '200': {
                    description: 'User list', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            users: { type: 'array', items: { $ref: '#/components/schemas/User' } },
                                            total: { type: 'integer' },
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin role required' },
            },
        },
        post: {
            tags: ['Users'],
            summary: 'Create new user',
            description: 'Create a new user account. Admin only.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['email', 'name', 'role'], properties: {
                                email: { type: 'string', format: 'email' },
                                name: { type: 'string' },
                                role: { type: 'string', enum: ['admin', 'analyst', 'viewer'] },
                            }
                        }
                    }
                },
            },
            responses: {
                '201': { description: 'User created', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/User' } } } } } },
                '400': { description: 'Missing required fields' },
                '409': { description: 'Email already exists' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin role required' },
            },
        },
    },
    '/v1/users/roles/list': {
        get: {
            tags: ['Users'],
            summary: 'Get available roles',
            description: 'List all available user roles with descriptions.',
            responses: {
                '200': {
                    description: 'Role list', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, description: { type: 'string' } } } },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/v1/users/{id}': {
        get: {
            tags: ['Users'],
            summary: 'Get user details',
            description: 'Get a single user by ID. Admin only.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'User details', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/User' } } } } } },
                '404': { description: 'User not found' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin role required' },
            },
        },
        put: {
            tags: ['Users'],
            summary: 'Update user',
            description: 'Update user fields. Admin only. Cannot change own role.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', properties: {
                                email: { type: 'string', format: 'email' },
                                name: { type: 'string' },
                                role: { type: 'string', enum: ['admin', 'analyst', 'viewer'] },
                                status: { type: 'string', enum: ['active', 'inactive', 'pending'] },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': { description: 'User updated', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/User' } } } } } },
                '403': { description: 'Cannot change own role' },
                '404': { description: 'User not found' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Users'],
            summary: 'Delete user',
            description: 'Delete a user account. Admin only. Cannot delete own account.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'User deleted' },
                '403': { description: 'Cannot delete own account' },
                '404': { description: 'User not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/v1/users/{id}/activate': {
        post: {
            tags: ['Users'],
            summary: 'Activate user',
            description: 'Activate a pending user account. Admin only.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'User activated', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/User' } } } } } },
                '404': { description: 'User not found' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin role required' },
            },
        },
    },
    '/v1/users/{id}/deactivate': {
        post: {
            tags: ['Users'],
            summary: 'Deactivate user',
            description: 'Deactivate a user account. Admin only. Cannot deactivate own account.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'User deactivated', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/User' } } } } } },
                '403': { description: 'Cannot deactivate own account' },
                '404': { description: 'User not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    // Admin (Queue Management)
    '/admin/stats': {
        get: {
            tags: ['Admin'],
            summary: 'Queue statistics',
            description: 'Get job counts for all BullMQ queues.',
            responses: {
                '200': {
                    description: 'Queue stats', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            queues: { type: 'object', additionalProperties: { $ref: '#/components/schemas/QueueStats' } },
                                            timestamp: { type: 'string', format: 'date-time' },
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/events': {
        get: {
            tags: ['Admin'],
            summary: 'Real-time queue events (SSE)',
            description: 'Server-Sent Events stream for real-time queue updates. Events: feed.completed, feed.failed, enrichment.completed, analysis.completed, notification.completed, alert.new, heartbeat.',
            responses: {
                '200': { description: 'SSE event stream', content: { 'text/event-stream': { schema: { type: 'string' } } } },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/jobs/feed-sync': {
        post: {
            tags: ['Admin'],
            summary: 'Trigger feed sync',
            description: 'Queue a feed sync job. Requires admin or analyst role.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', properties: {
                                source: { type: 'string', default: 'all', enum: ['all', 'alienvault', 'abusessl', 'cisa-kev'] },
                                options: { type: 'object', additionalProperties: true },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': {
                    description: 'Job queued', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { jobId: { type: 'string' }, queue: { type: 'string' }, source: { type: 'string' }, status: { type: 'string' } } },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin or analyst role required' },
            },
        },
    },
    '/admin/jobs/enrichment': {
        post: {
            tags: ['Admin'],
            summary: 'Queue IOC enrichment',
            description: 'Queue an IOC enrichment job. Requires admin or analyst role.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['iocId', 'iocValue', 'iocType'], properties: {
                                iocId: { type: 'string' },
                                iocValue: { type: 'string', example: '192.168.1.1' },
                                iocType: { type: 'string', enum: ['ip', 'domain', 'hash-sha256', 'hash-md5', 'url'] },
                                sources: { type: 'array', items: { type: 'string' } },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': { description: 'Job queued' },
                '400': { description: 'Missing required fields' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin or analyst role required' },
            },
        },
    },
    '/admin/jobs/ai-analysis': {
        post: {
            tags: ['Admin'],
            summary: 'Queue AI analysis',
            description: 'Queue an AI threat analysis job. Requires admin or analyst role.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['iocId', 'iocValue'], properties: {
                                iocId: { type: 'string' },
                                iocValue: { type: 'string' },
                                analysisType: { type: 'string', default: 'threat-assessment' },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': { description: 'Job queued' },
                '400': { description: 'Missing required fields' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin or analyst role required' },
            },
        },
    },
    '/admin/jobs/notification': {
        post: {
            tags: ['Admin'],
            summary: 'Queue notification',
            description: 'Queue a notification job (Slack, Email, or Webhook). Requires admin or analyst role.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', required: ['channel', 'target', 'payload'], properties: {
                                channel: { type: 'string', enum: ['slack', 'email', 'webhook'] },
                                target: { type: 'string', description: 'Webhook URL or email address' },
                                payload: { type: 'object', properties: { type: { type: 'string' }, severity: { type: 'string' }, title: { type: 'string' }, message: { type: 'string' } } },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': { description: 'Job queued' },
                '400': { description: 'Missing required fields' },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin or analyst role required' },
            },
        },
    },
    '/admin/jobs/neo4j-sync': {
        post: {
            tags: ['Admin'],
            summary: 'Trigger Postgres → Neo4j sync',
            description: 'Queue a Postgres to Neo4j graph sync job. Requires admin or analyst role.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object', properties: {
                                syncType: { type: 'string', default: 'all-iocs', enum: ['all-iocs', 'incremental', 'actors', 'vulnerabilities'] },
                                options: { type: 'object', additionalProperties: true },
                            }
                        }
                    }
                },
            },
            responses: {
                '200': {
                    description: 'Sync job queued', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { jobId: { type: 'string' }, queue: { type: 'string' }, syncType: { type: 'string' }, status: { type: 'string' } } },
                                }
                            }
                        }
                    }
                },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin or analyst role required' },
            },
        },
    },
    '/admin/jobs/{queue}/{jobId}': {
        get: {
            tags: ['Admin'],
            summary: 'Get job status',
            description: 'Get the current status, progress, and result of a specific job.',
            parameters: [
                { name: 'queue', in: 'path', required: true, schema: { type: 'string', enum: ['feed-sync', 'ioc-enrichment', 'ai-analysis', 'notifications', 'neo4j-sync'] } },
                { name: 'jobId', in: 'path', required: true, schema: { type: 'string' } },
            ],
            responses: {
                '200': {
                    description: 'Job status', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { $ref: '#/components/schemas/JobStatus' },
                                }
                            }
                        }
                    }
                },
                '404': { description: 'Queue or job not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // Config — Feeds CRUD
    // =========================================================================
    '/admin/config/feeds': {
        get: {
            tags: ['Admin'],
            summary: 'List feed configurations',
            description: 'Returns all feed definitions (built-in and custom).',
            responses: {
                '200': {
                    description: 'Feed list', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'array', items: { $ref: '#/components/schemas/FeedConfig' } },
                                },
                            },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin role required' },
            },
        },
        post: {
            tags: ['Admin'],
            summary: 'Add custom feed',
            description: 'Create a new custom feed definition.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['name', 'source'],
                            properties: {
                                name: { type: 'string', example: 'Custom OSINT Feed' },
                                source: { type: 'string', example: 'custom-api' },
                                description: { type: 'string' },
                                cron: { type: 'string', example: '0 */6 * * *' },
                                enabled: { type: 'boolean', default: true },
                                category: { type: 'string' },
                                url: { type: 'string' },
                                format: { type: 'string', enum: ['json', 'csv', 'rss', 'stix', 'text'] },
                                authHeader: { type: 'string' },
                                authKeyRef: { type: 'string' },
                                requiresApiKey: { type: 'string' },
                            },
                        },
                    },
                },
            },
            responses: {
                '201': {
                    description: 'Feed created', content: {
                        'application/json': {
                            schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/FeedConfig' } } },
                        },
                    },
                },
                '400': { description: 'Missing name or source' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/config/feeds/{id}': {
        put: {
            tags: ['Admin'],
            summary: 'Update feed configuration',
            description: 'Update cron schedule or enabled status of a feed.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                cron: { type: 'string' },
                                enabled: { type: 'boolean' },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': { description: 'Feed updated', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/FeedConfig' } } } } } },
                '404': { description: 'Feed not found' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Admin'],
            summary: 'Delete custom feed',
            description: 'Delete a custom feed definition. Built-in feeds cannot be deleted.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Feed deleted' },
                '404': { description: 'Custom feed not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // Config — API Keys CRUD
    // =========================================================================
    '/admin/config/api-keys': {
        get: {
            tags: ['Admin'],
            summary: 'List API key slots',
            description: 'Returns all API key slot definitions with masked values and configuration status.',
            responses: {
                '200': {
                    description: 'API key list', content: {
                        'application/json': {
                            schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { $ref: '#/components/schemas/ApiKeyConfig' } } } },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
            },
        },
        post: {
            tags: ['Admin'],
            summary: 'Add custom API key slot',
            description: 'Create a new API key slot with optional initial value.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['name', 'provider', 'envVar'],
                            properties: {
                                name: { type: 'string' },
                                provider: { type: 'string' },
                                envVar: { type: 'string' },
                                testEndpoint: { type: 'string' },
                                authHeaderName: { type: 'string' },
                                value: { type: 'string', description: 'Initial API key value' },
                            },
                        },
                    },
                },
            },
            responses: {
                '201': { description: 'API key slot created', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/ApiKeyConfig' } } } } } },
                '400': { description: 'Missing required fields' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/config/api-keys/{id}': {
        put: {
            tags: ['Admin'],
            summary: 'Update API key value',
            description: 'Set or update the value of an API key slot.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: {
                required: true,
                content: { 'application/json': { schema: { type: 'object', required: ['value'], properties: { value: { type: 'string' } } } } },
            },
            responses: {
                '200': { description: 'API key updated' },
                '404': { description: 'API key slot not found' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Admin'],
            summary: 'Delete custom API key slot',
            description: 'Delete a custom API key slot. Built-in slots cannot be deleted.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'API key slot deleted' },
                '404': { description: 'Custom API key not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/config/api-keys/{id}/test': {
        post: {
            tags: ['Admin'],
            summary: 'Test API key connectivity',
            description: 'Test if the configured API key works by calling the slot\'s test endpoint.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': {
                    description: 'Test result', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            configured: { type: 'boolean' },
                                            working: { type: 'boolean' },
                                            latency: { type: 'integer' },
                                            error: { type: 'string', nullable: true },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // Config — Services CRUD
    // =========================================================================
    '/admin/config/services': {
        get: {
            tags: ['Admin'],
            summary: 'List service connections',
            description: 'Returns all service connection definitions.',
            responses: {
                '200': { description: 'Service list', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { $ref: '#/components/schemas/ServiceConfig' } } } } } } },
                '401': { description: 'Unauthorized' },
            },
        },
        post: {
            tags: ['Admin'],
            summary: 'Add custom service',
            description: 'Create a new service connection definition.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['name', 'envVars'],
                            properties: {
                                name: { type: 'string' },
                                envVars: { type: 'array', items: { type: 'object', properties: { key: { type: 'string' }, label: { type: 'string' }, secret: { type: 'boolean' } } } },
                                values: { type: 'object', additionalProperties: { type: 'string' } },
                            },
                        },
                    },
                },
            },
            responses: {
                '201': { description: 'Service created', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/ServiceConfig' } } } } } },
                '400': { description: 'Missing required fields' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/config/services/{id}': {
        put: {
            tags: ['Admin'],
            summary: 'Update service connection',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
            responses: {
                '200': { description: 'Service updated' },
                '404': { description: 'Service not found' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Admin'],
            summary: 'Delete custom service',
            description: 'Delete a custom service connection. Built-in services cannot be deleted.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Service deleted' },
                '404': { description: 'Custom service not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // Config — Settings KV
    // =========================================================================
    '/admin/config/settings': {
        get: {
            tags: ['Admin'],
            summary: 'List runtime settings',
            description: 'Returns all configurable runtime settings (LOG_LEVEL, feature flags, etc.).',
            responses: {
                '200': {
                    description: 'Settings map', content: {
                        'application/json': {
                            schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object', additionalProperties: { type: 'string', nullable: true } } } },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/config/settings/{key}': {
        put: {
            tags: ['Admin'],
            summary: 'Update runtime setting',
            description: 'Set a runtime configuration value (overrides .env defaults via Redis).',
            parameters: [{ name: 'key', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['value'], properties: { value: { type: 'string' } } } } } },
            responses: {
                '200': { description: 'Setting updated' },
                '400': { description: 'Missing value' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Admin'],
            summary: 'Reset setting to default',
            description: 'Remove the Redis override and fall back to .env default.',
            parameters: [{ name: 'key', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Setting reset' },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // Users — Roles & Permissions CRUD
    // =========================================================================
    '/admin/users/roles/list': {
        get: {
            tags: ['Users'],
            summary: 'List roles and permission modules',
            description: 'Returns all roles with their default permissions, and all permission modules.',
            responses: {
                '200': {
                    description: 'Roles and permissions', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            roles: { type: 'array', items: { $ref: '#/components/schemas/Role' } },
                                            permissionModules: { type: 'array', items: { $ref: '#/components/schemas/PermissionModule' } },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/users/roles': {
        post: {
            tags: ['Users'],
            summary: 'Create role',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['id', 'name'],
                            properties: {
                                id: { type: 'string' },
                                name: { type: 'string' },
                                description: { type: 'string' },
                                defaultPermissions: { type: 'array', items: { type: 'string' } },
                            },
                        },
                    },
                },
            },
            responses: {
                '201': { description: 'Role created', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/Role' } } } } } },
                '400': { description: 'Missing required fields or duplicate ID' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/users/roles/{id}': {
        put: {
            tags: ['Users'],
            summary: 'Update role',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: {
                required: true,
                content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, defaultPermissions: { type: 'array', items: { type: 'string' } } } } } },
            },
            responses: {
                '200': { description: 'Role updated' },
                '404': { description: 'Role not found' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Users'],
            summary: 'Delete role',
            description: 'Delete a custom role. System roles cannot be deleted.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Role deleted' },
                '404': { description: 'Role not found or is a system role' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/users/permissions': {
        post: {
            tags: ['Users'],
            summary: 'Create permission module',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['id', 'name'],
                            properties: {
                                id: { type: 'string' },
                                name: { type: 'string' },
                                icon: { type: 'string' },
                                permissions: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, description: { type: 'string' } } } },
                            },
                        },
                    },
                },
            },
            responses: {
                '201': { description: 'Permission module created' },
                '400': { description: 'Missing required fields' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/users/permissions/{id}': {
        put: {
            tags: ['Users'],
            summary: 'Update permission module',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            requestBody: {
                required: true,
                content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, icon: { type: 'string' }, permissions: { type: 'array', items: { type: 'object' } } } } } },
            },
            responses: {
                '200': { description: 'Permission module updated' },
                '404': { description: 'Permission module not found' },
                '401': { description: 'Unauthorized' },
            },
        },
        delete: {
            tags: ['Users'],
            summary: 'Delete permission module',
            description: 'Delete a custom permission module. System modules cannot be deleted.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
            responses: {
                '200': { description: 'Permission module deleted' },
                '404': { description: 'Permission module not found or is a system module' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/users/{id}/regenerate-token': {
        post: {
            tags: ['Users'],
            summary: 'Regenerate API token',
            description: 'Generate a new random API token for the specified user.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
            responses: {
                '200': {
                    description: 'New token generated', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: { type: 'object', properties: { token: { type: 'string' }, maskedToken: { type: 'string' } } },
                                },
                            },
                        },
                    },
                },
                '404': { description: 'User not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // Audit Logs
    // =========================================================================
    '/admin/audit': {
        get: {
            tags: ['Audit'],
            summary: 'List audit entries',
            description: 'Query audit logs with filters for entity type, action, and date range.',
            parameters: [
                { name: 'entityType', in: 'query', schema: { type: 'string', enum: ['ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware'] } },
                { name: 'action', in: 'query', schema: { type: 'string', enum: ['create', 'update', 'delete', 'merge', 'enrich'] } },
                { name: 'from', in: 'query', schema: { type: 'string', format: 'date-time' } },
                { name: 'to', in: 'query', schema: { type: 'string', format: 'date-time' } },
                { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                { name: 'limit', in: 'query', schema: { type: 'integer', default: 50, maximum: 100 } },
            ],
            responses: {
                '200': {
                    description: 'Paginated audit entries', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            entries: { type: 'array', items: { $ref: '#/components/schemas/AuditEntry' } },
                                            total: { type: 'integer' },
                                            page: { type: 'integer' },
                                            limit: { type: 'integer' },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
                '403': { description: 'Admin or auditor role required' },
            },
        },
    },
    '/admin/audit/stats': {
        get: {
            tags: ['Audit'],
            summary: 'Audit statistics',
            description: 'Aggregated counts of audit actions and entity types over a time window.',
            parameters: [
                { name: 'days', in: 'query', schema: { type: 'integer', default: 30, minimum: 1, maximum: 365 } },
            ],
            responses: {
                '200': {
                    description: 'Audit statistics', content: {
                        'application/json': {
                            schema: {
                                type: 'object', properties: {
                                    success: { type: 'boolean' },
                                    data: {
                                        type: 'object', properties: {
                                            total: { type: 'integer' },
                                            days: { type: 'integer' },
                                            byAction: { type: 'array', items: { type: 'object', properties: { action: { type: 'string' }, count: { type: 'integer' } } } },
                                            byEntity: { type: 'array', items: { type: 'object', properties: { entityType: { type: 'string' }, count: { type: 'integer' } } } },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/audit/{id}': {
        get: {
            tags: ['Audit'],
            summary: 'Get audit entry detail',
            description: 'Retrieve a single audit entry with full change diff.',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
            responses: {
                '200': {
                    description: 'Audit entry', content: {
                        'application/json': {
                            schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/AuditEntry' } } },
                        },
                    },
                },
                '404': { description: 'Audit entry not found' },
                '401': { description: 'Unauthorized' },
            },
        },
    },

    // =========================================================================
    // API Sandbox
    // =========================================================================
    '/admin/sandbox/test-feed': {
        post: {
            tags: ['Admin'],
            summary: 'Test feed connectivity',
            description: 'Test connectivity to a feed URL. Makes a GET request with optional authentication. Rate-limited to 5 calls/minute.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['url'],
                            properties: {
                                url: { type: 'string', example: 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8' },
                                authHeader: { type: 'string', example: 'x-apikey' },
                                authValue: { type: 'string', description: 'API key or token value' },
                                method: { type: 'string', enum: ['GET', 'POST', 'HEAD'], default: 'GET' },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': {
                    description: 'Connectivity test result', content: {
                        'application/json': {
                            schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/SandboxResult' } } },
                        },
                    },
                },
                '400': { description: 'Missing URL' },
                '429': { description: 'Rate limit exceeded' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
    '/admin/sandbox/test-endpoint': {
        post: {
            tags: ['Admin'],
            summary: 'Test arbitrary endpoint',
            description: 'Generic endpoint tester — make an HTTP request to any URL with custom headers and body. Rate-limited.',
            requestBody: {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            required: ['url'],
                            properties: {
                                url: { type: 'string' },
                                method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'], default: 'GET' },
                                headers: { type: 'object', additionalProperties: { type: 'string' } },
                                body: { type: 'object', additionalProperties: true },
                                timeoutMs: { type: 'integer', default: 10000, maximum: 30000 },
                            },
                        },
                    },
                },
            },
            responses: {
                '200': {
                    description: 'Endpoint test result', content: {
                        'application/json': {
                            schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { $ref: '#/components/schemas/SandboxResult' } } },
                        },
                    },
                },
                '400': { description: 'Missing URL' },
                '429': { description: 'Rate limit exceeded' },
                '401': { description: 'Unauthorized' },
            },
        },
    },
} as const;
