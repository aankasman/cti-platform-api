DO $$ BEGIN
 CREATE TYPE "public"."key_status" AS ENUM('active', 'revoked', 'expired');
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 CREATE TYPE "public"."subscription_tier" AS ENUM('free', 'pro', 'enterprise');
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "relationships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source_type" varchar(64) NOT NULL,
	"source_id" varchar(128) NOT NULL,
	"relationship_type" varchar(64) NOT NULL,
	"target_type" varchar(64) NOT NULL,
	"target_id" varchar(128) NOT NULL,
	"description" text,
	"confidence" integer,
	"first_seen" timestamp,
	"last_seen" timestamp,
	"source" varchar(64) DEFAULT 'mitre',
	"raw_data" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "tools" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"mitre_id" varchar(64),
	"name" varchar(256) NOT NULL,
	"aliases" jsonb,
	"description" text,
	"type" varchar(64),
	"platforms" jsonb,
	"technique_ids" jsonb,
	"url" varchar(512),
	"source" varchar(64) DEFAULT 'mitre',
	"raw_data" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "tools_mitre_id_unique" UNIQUE("mitre_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "tactics" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"mitre_id" varchar(20) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"short_name" varchar(64),
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "tactics_mitre_id_unique" UNIQUE("mitre_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "techniques" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"mitre_id" varchar(20) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"detection" text,
	"platforms" jsonb,
	"permissions" jsonb,
	"data_sources" jsonb,
	"is_subtechnique" boolean DEFAULT false,
	"parent_id" varchar(20),
	"tactic_ids" jsonb,
	"url" varchar(512),
	"version" varchar(20),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "techniques_mitre_id_unique" UNIQUE("mitre_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "api_consumers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(256) NOT NULL,
	"email" varchar(256) NOT NULL,
	"organization" varchar(256),
	"tier" "subscription_tier" DEFAULT 'free' NOT NULL,
	"quota_monthly" integer DEFAULT 1000 NOT NULL,
	"quota_used" integer DEFAULT 0 NOT NULL,
	"quota_reset_date" timestamp,
	"rate_limit_rpm" integer DEFAULT 60 NOT NULL,
	"features" jsonb DEFAULT '{}'::jsonb,
	"is_active" boolean DEFAULT true NOT NULL,
	"verified_at" timestamp,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "api_consumers_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "api_usage" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"consumer_id" uuid,
	"key_id" uuid,
	"endpoint" varchar(256) NOT NULL,
	"method" varchar(10) NOT NULL,
	"status_code" integer NOT NULL,
	"latency_ms" integer,
	"response_size" integer,
	"ip_address" varchar(45),
	"user_agent" varchar(512),
	"timestamp" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "consumer_api_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"consumer_id" uuid NOT NULL,
	"key_hash" varchar(128) NOT NULL,
	"key_prefix" varchar(12) NOT NULL,
	"name" varchar(128),
	"status" "key_status" DEFAULT 'active' NOT NULL,
	"permissions" jsonb DEFAULT '[]'::jsonb,
	"last_used_at" timestamp,
	"usage_count" integer DEFAULT 0 NOT NULL,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"revoked_at" timestamp,
	CONSTRAINT "consumer_api_keys_key_hash_unique" UNIQUE("key_hash")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "consumer_webhooks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"consumer_id" uuid NOT NULL,
	"url" varchar(512) NOT NULL,
	"secret" varchar(128),
	"events" jsonb DEFAULT '[]'::jsonb,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_triggered_at" timestamp,
	"failure_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "api_usage" ADD CONSTRAINT "api_usage_consumer_id_api_consumers_id_fk" FOREIGN KEY ("consumer_id") REFERENCES "public"."api_consumers"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "api_usage" ADD CONSTRAINT "api_usage_key_id_consumer_api_keys_id_fk" FOREIGN KEY ("key_id") REFERENCES "public"."consumer_api_keys"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "consumer_api_keys" ADD CONSTRAINT "consumer_api_keys_consumer_id_api_consumers_id_fk" FOREIGN KEY ("consumer_id") REFERENCES "public"."api_consumers"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "consumer_webhooks" ADD CONSTRAINT "consumer_webhooks_consumer_id_api_consumers_id_fk" FOREIGN KEY ("consumer_id") REFERENCES "public"."api_consumers"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "consumers_email_idx" ON "api_consumers" ("email");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "consumers_tier_idx" ON "api_consumers" ("tier");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "usage_consumer_idx" ON "api_usage" ("consumer_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "usage_timestamp_idx" ON "api_usage" ("timestamp");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "usage_endpoint_idx" ON "api_usage" ("endpoint");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "keys_consumer_idx" ON "consumer_api_keys" ("consumer_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "keys_hash_idx" ON "consumer_api_keys" ("key_hash");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "keys_prefix_idx" ON "consumer_api_keys" ("key_prefix");