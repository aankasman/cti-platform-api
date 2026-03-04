CREATE TABLE IF NOT EXISTS "webhook_delivery_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"event_type" varchar(100) NOT NULL,
	"payload" jsonb NOT NULL,
	"attempt_number" integer DEFAULT 1,
	"request_headers" jsonb,
	"request_body" text,
	"response_status" integer,
	"response_body" text,
	"response_time_ms" integer,
	"status" varchar(20) NOT NULL,
	"error_message" text,
	"delivered_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "webhook_subscriptions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(255) NOT NULL,
	"url" text NOT NULL,
	"secret" varchar(255),
	"events" jsonb DEFAULT '["*"]'::jsonb,
	"filters" jsonb DEFAULT '{}'::jsonb,
	"is_active" boolean DEFAULT true,
	"last_delivery_at" timestamp with time zone,
	"last_delivery_status" varchar(20),
	"failure_count" integer DEFAULT 0,
	"headers" jsonb DEFAULT '{}'::jsonb,
	"created_by" varchar(255),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "webhook_delivery_logs" ADD CONSTRAINT "webhook_delivery_logs_subscription_id_webhook_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."webhook_subscriptions"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "webhook_delivery_logs_subscription_idx" ON "webhook_delivery_logs" ("subscription_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "webhook_delivery_logs_event_type_idx" ON "webhook_delivery_logs" ("event_type");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "webhook_delivery_logs_status_idx" ON "webhook_delivery_logs" ("status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "webhook_subscriptions_url_idx" ON "webhook_subscriptions" ("url");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "webhook_subscriptions_is_active_idx" ON "webhook_subscriptions" ("is_active");