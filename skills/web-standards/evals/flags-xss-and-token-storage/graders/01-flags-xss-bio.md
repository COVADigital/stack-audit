---
type: llm
focus: trace
weight: 1
---

The response flags `dangerouslySetInnerHTML` with the user-supplied `bio` in src/app/u/[name]/page.tsx as an XSS risk and recommends sanitizing it (e.g. DOMPurify) or rendering it as text.
