---
name: web-standards
description: Engineering standards for React / Next.js apps across 9 domains (git security, rendering & caching strategy, performance & Core Web Vitals, state management, networking, caching, architecture, frontend security, accessibility & i18n), tuned for Next.js 16 + React 19. Use when scoping a page or feature (rendering strategy, cache plan, state homes, API contract), when writing or reviewing data fetching, Server Actions, forms, auth/session, headers/CSP, caching or UI code, before a PR ("is this ready", "audit this repo", "check standards", "pre-PR checklist"), and before deploying ("launch checklist", "verify headers", "perf budget"). Not for deep diff security review (security-review), visual design critique (impeccable), running browser flows (playwright-cli), Docker files (container-standards) or OWASP/ASVS questions (owasp-security).
allowed-tools: Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/stack_profile.py *), Bash(python ${CLAUDE_PLUGIN_ROOT}/skills/web-standards/scripts/*)
---

# Web Standards

Every **Rule** line in `references/` is a requirement. Findings and advice cite rule IDs such as `sec.16`, meaning section 16 of `08-security.md`. `references/rule-index.md` lists all 179 rules, with how each one is checked.

## 0. Detect the stack first (always)

```bash
python ${CLAUDE_PLUGIN_ROOT}/scripts/stack_profile.py --root <repo>
```

Adapt every recommendation to what it reports:

- **Next.js major version.** On 16+: `proxy.ts` (not `middleware.ts`), `revalidateTag(tag, 'max')`, `updateTag` in Server Actions, `<Image preload>` (not `priority`), ESLint CLI (no `next lint`), async `cookies()`/`headers()`.
- **`cacheComponents` on or off.** It decides between `'use cache'`/`cacheLife`/`cacheTag` and legacy segment config. Read `references/next16-cache-model.md` before any caching advice.
- **`reactCompiler`, Zod major, ORM, auth library, i18n library, router (app/pages).**
- **Notes** (for example "`middleware.ts` on Next.js 16" or "`next lint` script"). Raise them with the user.

Never recommend an API the detected version doesn't have. In a monorepo, run the profile against the app directory.

## 1. Pick the phase

| The user is… | Phase | Read first |
|---|---|---|
| Planning a page or feature | **Scope** | 02 §20 (strategy table), `next16-cache-model.md`, 04 §20 (store table), 05 §19 (contracts), 09 §14 (WCAG target), 03 §18 (budgets) |
| Writing code | **Develop** | Only the reference for the code being touched (see the routing table below) |
| Asking "ready for PR?" | **Review** | `rule-index.md`, then the files for the domains the diff touches |
| Shipping or deploying | **Publish** | 03 §18–20, 06 §01/§08, 08 §13/§19, 01 §02 |

| Code being touched | Reference |
|---|---|
| Page, layout, route, metadata, Suspense | `02-rendering.md` |
| Images, fonts, bundles, lists, Web Vitals | `03-performance.md` |
| useState, stores, forms, URL state, optimistic UI | `04-state-management.md` |
| fetch, route handlers, Server Actions, retries, CORS | `05-networking.md` |
| Cache-Control, `'use cache'`, revalidation, service workers | `06-caching.md` + `next16-cache-model.md` |
| Folders, features, imports, tokens, flags, DAL | `07-architecture.md` |
| Auth, cookies, CSP, headers, secrets, input handling | `08-security.md` |
| Markup, forms, focus, contrast, motion, translations | `09-accessibility-i18n.md` |
| Repo setup, CI, hooks, tokens, branch protection | `01-git-security.md` |

Load sections, not whole files, when you only need one concept.

## 2. Scope phase output

Produce a short decision record for the PR description or the route header (template: `assets/route-decision-header.txt`):

- rendering strategy and why
- cache plan: layer, key, `cacheLife`, invalidation tag and API
- state classification: local / global / server / URL / form / persisted
- where the API contract lives
- a11y/i18n requirements
- perf budget

## 3. Review phase

**Automated audits** (read-only). Run each script as **one command with this full path** (no `S=` variable, `cd`, `&&` or pipes), so it matches the skill's pre-approved commands and runs without a permission prompt. Start with the orchestrator:

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/web-standards/scripts/run_audit.py --root <app> --phase review [--changed] --format json   # all 9 domains, merged + de-duplicated
python ${CLAUDE_PLUGIN_ROOT}/skills/web-standards/scripts/run_audit.py --root <app> --phase publish [--url https://…]          # + build output (bundle budgets, bundle secrets) + live headers
python ${CLAUDE_PLUGIN_ROOT}/skills/web-standards/scripts/run_audit.py --root <app> --phase scope                               # stack profile + route inventory
python ${CLAUDE_PLUGIN_ROOT}/skills/web-standards/scripts/run_audit.py --root <app> --domain sec,a11y                           # a subset
```

Single domains: `audit_security.py` (sec), `audit_git.py` (git), `audit_a11y_i18n.py` (a11y + contrast + message keys), `audit_rendering.py` (ren + **route inventory**), `audit_networking.py` (net), `audit_performance.py` (perf; `--build` = per-route gzipped initial JS vs budget), `audit_caching.py` (cache), `audit_architecture.py` (arch; import cycles, boundaries, env docs), `audit_state.py` (state), `probe_headers.py --url` (live cache/security headers), `contrast.py "#777" "#fff"`.

- In a monorepo, point `--root` at the app (for example `web/`). Repo-level files (`.github/`, hooks, `.gitignore`) are read from the git toplevel automatically.
- Ask before using `--audit`, `--scan`, `--remote` or `--url` (they contact a registry, run a local tool over history, query GitHub, or request the live site). Only probe sites the user owns.
- **Missing scanner (gitleaks for `--scan`).** The scripts never install anything; they report what is missing. When that happens, ask the user which they want: (1) run it once from the tool's official container image, with nothing installed (needs Docker; pin a version tag); (2) install it system-wide with their package manager, from the tool's official source; (3) skip it, and list the check under "Not checked". Confirm the exact command against the tool's official documentation, show it, and run it only after they choose.
- **Triage before reporting.** Open the file for every `confidence: medium/low` finding and confirm it. Drop false positives, and say how many you dropped. Real-repo trials showed common false-positive shapes (auth inside wrapper helpers, validation in another module), so read the surrounding code.
- Report findings grouped by severity: severity · `rule-id` · `file:line` · problem · fix. Don't paste raw JSON.

**Manual rules** (55 of 179, listed under each report's "Not checked"): walk them in `rule-index.md` for the domains the change touches, and give your assessment.

Always end with **"Not checked"**: each script's `not_checked` list plus anything you couldn't assess. Never imply coverage you didn't have.

## 4. Delegation

- Runtime accessibility (axe), keyboard and screenshot passes: **playwright-cli**, using `assets/axe.spec.ts` as the starting test.
- Deep security review of a diff: **security-review**. OWASP depth or ASVS mapping: **owasp-security** (each security section in `08-security.md` ends with an OWASP mapping table).
- Visual and UX quality: **impeccable**.
- Library APIs not covered here: **context7**, matching the repo's installed versions.

## 5. Fixing and templates

- Change code only when the user asks. Keep fixes to the smallest scope, and cite the rule ID in the summary.
- `assets/` holds starting templates: `gitignore.nextjs`, `dependabot.yml`, `pre-commit-config.yaml`, `lighthouserc.json`, `security-headers.next.config.ts`, `proxy.csp.ts`, `axe.spec.ts`, `adr-template.md`, `route-decision-header.txt`, `stack-audit.config.json`, `ci-stack-audit.yml` (runs these audits in GitHub Actions with code-scanning upload). Copy one in only on request, and adapt it to the repo: never overwrite an existing file without showing the diff.

## 6. Suppressions (for audit output)

- Inline: `// stack-audit-ignore sec.01 -- sanitized by DOMPurify in lib/html.ts` (also `#` and `{/* */}` comments, and `sec.*` wildcards).
- Per path: `stack-audit.config.json` → `{ "ignore": { "sec.01": ["src/legacy/**"] } }`.
- A suppression without a reason doesn't suppress anything, and is itself reported as `meta.01`.

## 7. Checks worth keeping

When you run a check of your own that isn't one of this plugin's rules and is likely to be needed again (a search for a project-specific mistake, a regression you just fixed), ask the user what to do with it before you finish:

1. **Keep it one-off.** Nothing is saved.
2. **Save it as a test in the project's existing test suite.** Suggest this first: it runs on every change and in CI, so the problem is caught again without anyone remembering it.
3. **Save it as a standalone script** in a folder they choose, for checks that don't fit a test.

Never save anything without asking, never add a test framework the project doesn't have, and show the file before writing it.
