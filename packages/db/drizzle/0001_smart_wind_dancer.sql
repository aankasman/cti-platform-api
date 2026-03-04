CREATE TABLE IF NOT EXISTS "iocs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"source" text NOT NULL,
	"threat_type" text,
	"confidence" integer,
	"severity" text,
	"first_seen" timestamp,
	"last_seen" timestamp,
	"tags" text[],
	"pulse_id" text,
	"raw_data" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "pulses" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"otx_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"author" text,
	"tlp" text,
	"tags" text[],
	"adversary" text,
	"targeted_countries" text[],
	"industries" text[],
	"malware_families" text[],
	"attack_ids" text[],
	"indicator_count" integer,
	"subscriber_count" integer,
	"otx_created" timestamp,
	"otx_modified" timestamp,
	"raw_data" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	"synced_at" timestamp,
	CONSTRAINT "pulses_otx_id_unique" UNIQUE("otx_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "vulnerabilities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"cve_id" text NOT NULL,
	"description" text,
	"cvss_score" numeric(3, 1),
	"cvss_vector" text,
	"severity" text,
	"cwe_id" text,
	"is_exploited" boolean DEFAULT false,
	"exploit_added_date" date,
	"due_date" date,
	"vendor_project" text,
	"product" text,
	"references" text[],
	"published_date" timestamp,
	"last_modified" timestamp,
	"raw_data" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	"synced_at" timestamp,
	CONSTRAINT "vulnerabilities_cve_id_unique" UNIQUE("cve_id")
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "iocs_type_idx" ON "iocs" ("type");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "iocs_source_idx" ON "iocs" ("source");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "iocs_value_idx" ON "iocs" ("value");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "iocs_threat_type_idx" ON "iocs" ("threat_type");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "pulses_otx_id_idx" ON "pulses" ("otx_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "pulses_adversary_idx" ON "pulses" ("adversary");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "vulnerabilities_cve_id_idx" ON "vulnerabilities" ("cve_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "vulnerabilities_severity_idx" ON "vulnerabilities" ("severity");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "vulnerabilities_is_exploited_idx" ON "vulnerabilities" ("is_exploited");