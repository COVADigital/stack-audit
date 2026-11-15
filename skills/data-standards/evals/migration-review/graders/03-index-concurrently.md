---
type: llm
focus: trace
weight: 1
---

The response notes that the plain CREATE INDEX on a 2-million-row table blocks writes while it builds and suggests CREATE INDEX CONCURRENTLY (which cannot run inside a transaction).
