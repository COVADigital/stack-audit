ALTER TABLE "users" ADD COLUMN "stripe_customer_id" text NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "plan" text DEFAULT 'free' NOT NULL;--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "legacy_plan";--> statement-breakpoint
CREATE INDEX "users_stripe_customer_idx" ON "users" ("stripe_customer_id");
