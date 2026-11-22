---
type: llm
focus: output
weight: 1
---

Corrects the pasted checklist instead of adopting it, and says what it changed and why. It must correct at least three of: `ssl_negotiation` is not a server setting (`sslnegotiation=direct` is a client option for PostgreSQL 17+, so it doesn't apply to this 16.x server); TLSv1.3-only can lock out older clients, so keep TLSv1.2 until every client is confirmed; `REVOKE TEMPORARY … FROM app_user` does nothing while the privilege comes from PUBLIC, so revoke it from PUBLIC; `REVOKE ALL ON SCHEMA public FROM PUBLIC` also removes USAGE, so revoke CREATE only; FORCE ROW LEVEL SECURITY on every table also restricts the owner's migrations, so it is staged per table, not done "today".
