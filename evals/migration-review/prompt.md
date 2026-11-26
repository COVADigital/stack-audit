---
tags: [stack-audit]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Bash]
---

drizzle generated drizzle/0001_billing.sql for our billing feature. is it safe to run against production? users has about 2 million rows and we deploy with zero downtime. dont run anything, just tell me

Input files: drizzle.config.ts, drizzle/0000_init.sql, drizzle/0001_billing.sql, src/db/schema.ts, package.json
