---
tags: [stack-audit]
max_turns: 40
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

we deploy this stack next week. go through compose.yaml and the service Dockerfiles and list every security problem, naming the service or file for each. dont run docker and dont change any files

Input files: compose.yaml, services/*/Dockerfile
