---
type: llm
focus: trace
weight: 1
---

The response flags `5432:5432` on the db service as reachable from the internet and explains that Docker-published ports bypass UFW; it suggests removing the port or binding to 127.0.0.1.
