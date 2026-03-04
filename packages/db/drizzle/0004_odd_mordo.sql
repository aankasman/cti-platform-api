DO $$ BEGIN
 CREATE TYPE "public"."audit_action" AS ENUM('create', 'update', 'delete', 'merge', 'enrich');
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 CREATE TYPE "public"."entity_type" AS ENUM('ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware');
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 CREATE TYPE "public"."ai_entity_type" AS ENUM('ioc', 'cve', 'actor');
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"entity_type" "entity_type" NOT NULL,
	"entity_id" uuid NOT NULL,
	"action" "audit_action" NOT NULL,
	"user_id" uuid,
	"api_key_id" uuid,
	"source" varchar(100),
	"changes" jsonb,
	"metadata" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "data_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"entity_type" "entity_type" NOT NULL,
	"entity_id" uuid NOT NULL,
	"version_number" varchar(20) NOT NULL,
	"data" jsonb NOT NULL,
	"data_hash" varchar(64) NOT NULL,
	"created_by" varchar(255),
	"source" varchar(100),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "ai_analysis_cache" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"entity_type" "ai_entity_type" NOT NULL,
	"entity_id" uuid NOT NULL,
	"analysis_data" jsonb NOT NULL,
	"provider" varchar(50) NOT NULL,
	"tokens_used" varchar(20),
	"entity_data_hash" varchar(64) NOT NULL,
	"analyzed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "campaign_indicators" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"campaign_id" uuid NOT NULL,
	"mention_id" uuid,
	"item_id" uuid,
	"added_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "campaigns" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(500) NOT NULL,
	"description" text,
	"status" varchar(20) DEFAULT 'active' NOT NULL,
	"severity" varchar(20),
	"first_seen" timestamp with time zone,
	"last_seen" timestamp with time zone,
	"indicator_count" integer DEFAULT 0,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "exa_websets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"exa_webset_id" varchar(255) NOT NULL,
	"category" varchar(50) NOT NULL,
	"title" varchar(500) NOT NULL,
	"status" varchar(20) DEFAULT 'active' NOT NULL,
	"exa_monitor_id" varchar(255),
	"item_count" integer DEFAULT 0,
	"last_sync_at" timestamp with time zone,
	"config" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "exa_websets_exa_webset_id_unique" UNIQUE("exa_webset_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "web_intel_items" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"exa_item_id" varchar(255),
	"webset_id" uuid,
	"category" varchar(50) NOT NULL,
	"title" varchar(2000),
	"url" text,
	"source_url" text,
	"author" varchar(500),
	"published_at" timestamp with time zone,
	"text_content" text,
	"summary" text,
	"highlights" jsonb DEFAULT '[]'::jsonb,
	"ai_summary" text,
	"extracted_entities" jsonb DEFAULT '{}'::jsonb,
	"enrichments" jsonb DEFAULT '{}'::jsonb,
	"ioc_extracted" boolean DEFAULT false,
	"embedding_generated" boolean DEFAULT false,
	"neo4j_synced" boolean DEFAULT false,
	"source_provider" varchar(20) DEFAULT 'exa',
	"platform" varchar(50),
	"severity" varchar(20),
	"confidence" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "web_intel_items_exa_item_id_unique" UNIQUE("exa_item_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "web_intel_mentions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"item_id" uuid NOT NULL,
	"type" varchar(30) NOT NULL,
	"value" varchar(2000) NOT NULL,
	"canonical_id" varchar(128) NOT NULL,
	"confidence" integer DEFAULT 0,
	"context" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "campaign_indicators" ADD CONSTRAINT "campaign_indicators_campaign_id_campaigns_id_fk" FOREIGN KEY ("campaign_id") REFERENCES "public"."campaigns"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "campaign_indicators" ADD CONSTRAINT "campaign_indicators_mention_id_web_intel_mentions_id_fk" FOREIGN KEY ("mention_id") REFERENCES "public"."web_intel_mentions"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "campaign_indicators" ADD CONSTRAINT "campaign_indicators_item_id_web_intel_items_id_fk" FOREIGN KEY ("item_id") REFERENCES "public"."web_intel_items"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "web_intel_items" ADD CONSTRAINT "web_intel_items_webset_id_exa_websets_id_fk" FOREIGN KEY ("webset_id") REFERENCES "public"."exa_websets"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "web_intel_mentions" ADD CONSTRAINT "web_intel_mentions_item_id_web_intel_items_id_fk" FOREIGN KEY ("item_id") REFERENCES "public"."web_intel_items"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_logs_entity_idx" ON "audit_logs" ("entity_type","entity_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_logs_action_idx" ON "audit_logs" ("action");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_logs_user_idx" ON "audit_logs" ("user_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_logs_created_at_idx" ON "audit_logs" ("created_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "data_versions_entity_version_idx" ON "data_versions" ("entity_type","entity_id","version_number");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "data_versions_hash_idx" ON "data_versions" ("data_hash");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "ai_analysis_cache_entity_idx" ON "ai_analysis_cache" ("entity_type","entity_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "ai_analysis_cache_entity_hash_idx" ON "ai_analysis_cache" ("entity_id","entity_data_hash");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "campaign_indicators_campaign_id_idx" ON "campaign_indicators" ("campaign_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "campaign_indicators_mention_id_idx" ON "campaign_indicators" ("mention_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "campaigns_status_idx" ON "campaigns" ("status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "campaigns_severity_idx" ON "campaigns" ("severity");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "exa_websets_category_idx" ON "exa_websets" ("category");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "exa_websets_status_idx" ON "exa_websets" ("status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "exa_websets_exa_id_idx" ON "exa_websets" ("exa_webset_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_category_idx" ON "web_intel_items" ("category");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_webset_id_idx" ON "web_intel_items" ("webset_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_published_at_idx" ON "web_intel_items" ("published_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_severity_idx" ON "web_intel_items" ("severity");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_platform_idx" ON "web_intel_items" ("platform");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_exa_item_id_idx" ON "web_intel_items" ("exa_item_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_items_source_provider_idx" ON "web_intel_items" ("source_provider");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_mentions_item_id_idx" ON "web_intel_mentions" ("item_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_mentions_type_idx" ON "web_intel_mentions" ("type");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_mentions_value_idx" ON "web_intel_mentions" ("value");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "web_intel_mentions_canonical_id_idx" ON "web_intel_mentions" ("canonical_id");