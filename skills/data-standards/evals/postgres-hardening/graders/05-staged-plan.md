---
type: llm
weight: 1
---

The remediation plan is ordered from zero-impact changes (patching, logging) through staging (roles, revokes, timeouts, RLS one table at a time) to production enforcement (hostssl/scram only after confirming no unencrypted sessions), and includes rollback steps. An immediate containment step before patching is correct, not out of order, when it closes an open exposure (the pg_hba trust line open to any address, a public port) and has its own check and rollback.
