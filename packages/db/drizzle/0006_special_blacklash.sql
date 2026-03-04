CREATE TABLE IF NOT EXISTS "api_key_slots" (
	"id" varchar(100) PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"provider" varchar(100) NOT NULL,
	"env_var" varchar(100) NOT NULL,
	"test_endpoint" text,
	"auth_header_name" varchar(100),
	"is_custom" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "feeds_config" (
	"id" varchar(100) PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"source" varchar(100) NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"cron" varchar(50) DEFAULT '0 * * * *' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"category" varchar(50) DEFAULT 'custom-api' NOT NULL,
	"requires_api_key" varchar(100),
	"is_custom" boolean DEFAULT false NOT NULL,
	"url" text,
	"auth_header" varchar(100),
	"auth_key_ref" varchar(100),
	"format" varchar(20),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "services_config" (
	"id" varchar(100) PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"env_vars" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"is_custom" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
