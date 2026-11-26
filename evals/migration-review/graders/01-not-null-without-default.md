---
type: llm
focus: trace
weight: 1
---

The response says that adding `stripe_customer_id` as NOT NULL without a DEFAULT fails on a table that already has rows, and suggests adding it nullable (then backfilling and setting NOT NULL) or giving it a default.
