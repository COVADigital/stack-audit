---
tags: [stack-audit]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

We receive Sanity webhooks at /api/revalidate in our Next.js app. What does OWASP actually recommend for securing a webhook endpoint like that? I need citations I can paste into our security doc.
