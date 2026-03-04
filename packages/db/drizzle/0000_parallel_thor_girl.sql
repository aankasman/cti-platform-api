CREATE TABLE IF NOT EXISTS "api_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"name" varchar(255) NOT NULL,
	"key_hash" varchar(64) NOT NULL,
	"key_prefix" varchar(8) NOT NULL,
	"permissions" jsonb DEFAULT '[]'::jsonb,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "api_keys_key_hash_unique" UNIQUE("key_hash")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"settings" jsonb DEFAULT '{}'::jsonb,
	"is_default" boolean DEFAULT false,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token" varchar(255) NOT NULL,
	"user_agent" text,
	"ip_address" varchar(45),
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sessions_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "user_organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"role" varchar(50) DEFAULT 'member' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar(255) NOT NULL,
	"name" varchar(255) NOT NULL,
	"password_hash" text,
	"api_token" varchar(64),
	"is_active" boolean DEFAULT true NOT NULL,
	"roles" jsonb DEFAULT '[]'::jsonb,
	"permissions" jsonb DEFAULT '[]'::jsonb,
	"last_login" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email"),
	CONSTRAINT "users_api_token_unique" UNIQUE("api_token")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "indicators" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"stix_id" varchar(255) NOT NULL,
	"pattern" text NOT NULL,
	"pattern_type" varchar(50) NOT NULL,
	"pattern_version" varchar(20),
	"name" varchar(500),
	"description" text,
	"valid_from" timestamp with time zone,
	"valid_until" timestamp with time zone,
	"labels" jsonb DEFAULT '[]'::jsonb,
	"kill_chain_phases" jsonb DEFAULT '[]'::jsonb,
	"external_references" jsonb DEFAULT '[]'::jsonb,
	"confidence" varchar(20),
	"created_by_ref" varchar(255),
	"object_marking_refs" jsonb DEFAULT '[]'::jsonb,
	"stix_created" timestamp with time zone,
	"stix_modified" timestamp with time zone,
	"synced_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "indicators_stix_id_unique" UNIQUE("stix_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "malware" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"stix_id" varchar(255) NOT NULL,
	"name" varchar(500) NOT NULL,
	"description" text,
	"malware_types" jsonb DEFAULT '[]'::jsonb,
	"is_family" varchar(10),
	"aliases" jsonb DEFAULT '[]'::jsonb,
	"capabilities" jsonb DEFAULT '[]'::jsonb,
	"labels" jsonb DEFAULT '[]'::jsonb,
	"external_references" jsonb DEFAULT '[]'::jsonb,
	"stix_created" timestamp with time zone,
	"stix_modified" timestamp with time zone,
	"synced_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "malware_stix_id_unique" UNIQUE("stix_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "sync_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"entity_type" varchar(100) NOT NULL,
	"status" varchar(20) NOT NULL,
	"items_processed" jsonb DEFAULT '0'::jsonb,
	"items_failed" jsonb DEFAULT '0'::jsonb,
	"last_sync_cursor" varchar(255),
	"error_message" text,
	"started_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "threat_actors" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"stix_id" varchar(255) NOT NULL,
	"name" varchar(500) NOT NULL,
	"description" text,
	"aliases" jsonb DEFAULT '[]'::jsonb,
	"sophistication" varchar(50),
	"resource_level" varchar(50),
	"primary_motivation" varchar(100),
	"secondary_motivations" jsonb DEFAULT '[]'::jsonb,
	"goals" jsonb DEFAULT '[]'::jsonb,
	"labels" jsonb DEFAULT '[]'::jsonb,
	"external_references" jsonb DEFAULT '[]'::jsonb,
	"confidence" varchar(20),
	"created_by_ref" varchar(255),
	"object_marking_refs" jsonb DEFAULT '[]'::jsonb,
	"stix_created" timestamp with time zone,
	"stix_modified" timestamp with time zone,
	"synced_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "threat_actors_stix_id_unique" UNIQUE("stix_id")
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "user_organizations" ADD CONSTRAINT "user_organizations_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "user_organizations" ADD CONSTRAINT "user_organizations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "indicators_pattern_idx" ON "indicators" ("pattern");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "indicators_pattern_type_idx" ON "indicators" ("pattern_type");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "indicators_stix_id_idx" ON "indicators" ("stix_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "malware_name_idx" ON "malware" ("name");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "malware_stix_id_idx" ON "malware" ("stix_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "threat_actors_name_idx" ON "threat_actors" ("name");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "threat_actors_stix_id_idx" ON "threat_actors" ("stix_id");