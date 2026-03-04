CREATE TABLE IF NOT EXISTS "sightings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ioc_id" uuid NOT NULL,
	"type" text DEFAULT 'sighting' NOT NULL,
	"source" text NOT NULL,
	"description" text,
	"confidence" integer DEFAULT 50,
	"count" integer DEFAULT 1,
	"observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "warninglist_entries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"warninglist_id" uuid NOT NULL,
	"value" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "warninglists" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"type" text NOT NULL,
	"category" text DEFAULT 'false_positive' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"source" text,
	"version" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "warninglists_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "playbook_executions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"playbook_id" uuid NOT NULL,
	"trigger_data" jsonb DEFAULT '{}'::jsonb,
	"status" text DEFAULT 'running' NOT NULL,
	"results" jsonb DEFAULT '[]'::jsonb,
	"error" text,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "playbooks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"trigger_event" text NOT NULL,
	"conditions" jsonb DEFAULT '{}'::jsonb,
	"actions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "permission_modules" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"icon" varchar(50) DEFAULT 'settings' NOT NULL,
	"permissions" jsonb DEFAULT '[]'::jsonb,
	"is_system" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "roles" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"default_permissions" jsonb DEFAULT '[]'::jsonb,
	"is_system" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "sightings" ADD CONSTRAINT "sightings_ioc_id_iocs_id_fk" FOREIGN KEY ("ioc_id") REFERENCES "public"."iocs"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "sightings" ADD CONSTRAINT "sightings_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "warninglist_entries" ADD CONSTRAINT "warninglist_entries_warninglist_id_warninglists_id_fk" FOREIGN KEY ("warninglist_id") REFERENCES "public"."warninglists"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "playbook_executions" ADD CONSTRAINT "playbook_executions_playbook_id_playbooks_id_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."playbooks"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "playbooks" ADD CONSTRAINT "playbooks_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "sightings_ioc_id_idx" ON "sightings" ("ioc_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "sightings_type_idx" ON "sightings" ("type");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "sightings_observed_at_idx" ON "sightings" ("observed_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "sightings_source_idx" ON "sightings" ("source");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "warninglist_entries_wl_id_idx" ON "warninglist_entries" ("warninglist_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "warninglist_entries_value_idx" ON "warninglist_entries" ("value");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "warninglists_enabled_idx" ON "warninglists" ("enabled");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "warninglists_category_idx" ON "warninglists" ("category");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "playbook_executions_pb_id_idx" ON "playbook_executions" ("playbook_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "playbook_executions_status_idx" ON "playbook_executions" ("status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "playbook_executions_started_at_idx" ON "playbook_executions" ("started_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "playbooks_trigger_event_idx" ON "playbooks" ("trigger_event");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "playbooks_enabled_idx" ON "playbooks" ("enabled");