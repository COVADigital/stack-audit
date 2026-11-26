---
type: llm
weight: 1
---

Flags that src/db/tenant.ts uses a session-level SET app.tenant_id, which leaks between requests on pooled connections, and recommends SET LOCAL or set_config(..., true) inside a transaction.
