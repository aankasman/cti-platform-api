DO $$ BEGIN
 CREATE TYPE "public"."organization_plan" AS ENUM('free', 'pro', 'enterprise');
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "organization_quotas" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"max_iocs" integer DEFAULT 10000 NOT NULL,
	"max_webhooks" integer DEFAULT 3 NOT NULL,
	"max_api_calls" integer DEFAULT 10000 NOT NULL,
	"max_export_size" integer DEFAULT 1000 NOT NULL,
	CONSTRAINT "organization_quotas_org_id_unique" UNIQUE("org_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "fight_group_techniques" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"group_id" varchar(128) NOT NULL,
	"group_name" varchar(256) NOT NULL,
	"fight_technique_id" varchar(64) NOT NULL,
	"technique_name" varchar(256),
	"description" text,
	"confidence" integer,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "fight_mitigations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"fight_id" varchar(64) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"technique_ids" jsonb,
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "fight_mitigations_fight_id_unique" UNIQUE("fight_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "fight_tactics" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"mitre_id" varchar(20) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"short_name" varchar(64),
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "fight_tactics_mitre_id_unique" UNIQUE("mitre_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "fight_techniques" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"fight_id" varchar(64) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"bluf" text,
	"status" varchar(128),
	"architecture_segment" varchar(256),
	"typecode" varchar(64),
	"tactic_ids" jsonb,
	"platforms" jsonb,
	"preconditions" jsonb,
	"postconditions" jsonb,
	"critical_assets" jsonb,
	"detections" jsonb,
	"procedure_examples" jsonb,
	"references" jsonb,
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "fight_techniques_fight_id_unique" UNIQUE("fight_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "atlas_case_studies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"atlas_id" varchar(64) NOT NULL,
	"name" varchar(512) NOT NULL,
	"summary" text,
	"incident_date" varchar(64),
	"reporter" varchar(256),
	"target" varchar(256),
	"actor" varchar(256),
	"technique_ids" jsonb,
	"procedure_steps" jsonb,
	"references" jsonb,
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "atlas_case_studies_atlas_id_unique" UNIQUE("atlas_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "atlas_mitigations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"atlas_id" varchar(64) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"technique_ids" jsonb,
	"ml_lifecycle" jsonb,
	"category" jsonb,
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "atlas_mitigations_atlas_id_unique" UNIQUE("atlas_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "atlas_tactics" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"atlas_id" varchar(20) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"attack_reference_id" varchar(20),
	"attack_reference_url" varchar(512),
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "atlas_tactics_atlas_id_unique" UNIQUE("atlas_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "atlas_techniques" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"atlas_id" varchar(64) NOT NULL,
	"name" varchar(256) NOT NULL,
	"description" text,
	"maturity" varchar(64),
	"subtechnique_of" varchar(64),
	"tactic_ids" jsonb,
	"attack_reference_id" varchar(20),
	"attack_reference_url" varchar(512),
	"url" varchar(512),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "atlas_techniques_atlas_id_unique" UNIQUE("atlas_id")
);
--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "slug" varchar(128);--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "plan" "organization_plan" DEFAULT 'free' NOT NULL;--> statement-breakpoint
ALTER TABLE "threat_actors" ADD COLUMN "country" varchar(100);--> statement-breakpoint
ALTER TABLE "threat_actors" ADD COLUMN "first_seen" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "threat_actors" ADD COLUMN "last_seen" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "iocs" ADD COLUMN "enrichment_score" integer;--> statement-breakpoint
ALTER TABLE "iocs" ADD COLUMN "enrichment_level" text;--> statement-breakpoint
ALTER TABLE "iocs" ADD COLUMN "enrichment_tags" text[];--> statement-breakpoint
ALTER TABLE "iocs" ADD COLUMN "enrichment_data" jsonb;--> statement-breakpoint
ALTER TABLE "iocs" ADD COLUMN "enriched_at" timestamp;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "organization_quotas" ADD CONSTRAINT "organization_quotas_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
ALTER TABLE "organizations" ADD CONSTRAINT "organizations_slug_unique" UNIQUE("slug");