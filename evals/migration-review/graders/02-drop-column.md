---
type: llm
focus: trace
weight: 1
---

The response warns that dropping `legacy_plan` deletes data and can break the app version still running during a zero-downtime deploy, and recommends removing its use first and/or taking a backup before dropping.
