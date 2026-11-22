---
type: llm
focus: output
weight: 1
---

The remediation plan is ordered from zero-impact changes (patching, logging) through staging (roles, revokes, timeouts, RLS one table at a time) to production enforcement (hostssl/scram only after confirming no unencrypted sessions), and includes rollback steps.
