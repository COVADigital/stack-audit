---
type: llm
focus: trace
weight: 1
---

The response flags that src/lib/api/orders.ts does not check `res.ok` (or has no timeout) on its fetch.
