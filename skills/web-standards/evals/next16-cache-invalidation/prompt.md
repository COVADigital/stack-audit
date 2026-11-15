---
tags: [stack-audit]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

We're on Next 16 with cacheComponents turned on. The products list is fetched in a 'use cache' function. When an admin edits a product through a server action the list stays stale. What's the right way to invalidate it now? Show me the code.
