---
type: llm
focus: trace
weight: 1
---

The response flags `NPM_TOKEN` passed as ARG/ENV in services/uploads/Dockerfile as a secret exposure, for example through the build stage's history, the build cache or the image. Noting that it doesn't reach the shipped image, because `deps` is not the final stage, is correct.
