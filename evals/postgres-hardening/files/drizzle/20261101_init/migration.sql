CREATE TABLE "projects" ("id" uuid PRIMARY KEY, "tenant_id" uuid NOT NULL, "name" text NOT NULL);
--> statement-breakpoint
ALTER TABLE "projects" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY "tenant_insert" ON "projects" AS PERMISSIVE FOR INSERT TO "app_user";
--> statement-breakpoint
CREATE VIEW "project_list" AS SELECT "id", "name" FROM "projects";
