# ASVS 5.0 Self-Assessment Method

> OWASP cheat sheets are **guidance**. The ASVS (Application Security Verification Standard) is the **verification standard**. This method produces an evidence-based **self-assessment** against ASVS 5.0 at a chosen level. It is never a certification or a claim of compliance.

`scripts/compliance_checklist.py` automates steps 2–4: scoping (via `map_controls.py`), evidence from the static audits, and the report shape below. The remaining work is assessing each `not assessed` row.

## 1. Choose the level

| Level | Use for | Default in this plugin |
|---|---|---|
| **L1** | Content and marketing sites, artist sites, low-risk apps without accounts | Sites with no login, payments or admin |
| **L2** | Apps with user accounts, personal data, payments or an admin area | Anything with accounts, payments or admin |
| **L3** | High-value or high-assurance systems (finance, health, critical infrastructure) | Only when the user asks |

Override per repo in `stack-audit.config.json` → `"asvs": { "level": 2 }`.

## 2. Scope the chapters

Skip chapters that clearly don't apply, and record why. For example, *V10 OAuth: not applicable, no OAuth flows* or *V4.3 GraphQL: not applicable*. Map the stack to chapters with `find_sheets.py --asvs V<n>` and the curated sets in `stack-profiles.md`.

## 3. Assess each section

For each in-scope ASVS section, record:

| Field | Values |
|---|---|
| Status | `met` · `partial` · `not met` · `n/a` · `not assessed` |
| Evidence | `file:line`, a config value, an audit finding ID (for example `sec.06`, `cnet.02`), or a human attestation ("Coolify scheduled backups enabled, verified 2026-11-13") |
| Gap / action | What is missing and the concrete fix, with an owner if known |
| Guidance | OWASP sheet › section citations (from `find_sheets.py` / `read_section.py`) |

Rules:

- **No evidence means `not assessed`, not `met`.** Never infer compliance from the absence of findings.
- **Automated findings are evidence of problems, not proof of safety.** A clean audit script supports `met` only for what that script actually checks (see each rule's check type in `web-standards/references/rule-index.md`).
- Sections that need runtime verification (TLS, headers on the live URL, rate limits) need a live check or an attestation.
- Requirement-level checks (V3.3.1, …) need the ASVS 5.0 requirement text, which is not in the cheat sheet repo. Until it's added, assess at **section level** and say so.

## 4. Report shape

1. **Header:** "ASVS 5.0 Level N self-assessment", repo, commit, date, catalog commit, assessor ("Claude, with …").
2. **Summary:** count of sections by status, plus the top 5 gaps by risk.
3. **Per chapter:** a table using the fields above, gaps first.
4. **Not assessed:** list each section with the reason (needs runtime check, out of scope, needs requirement text).
5. **Disclaimer:** "This is a self-assessment against OWASP ASVS 5.0 section-level mappings. It is not an audit, certification, or attestation of compliance."

## 5. Top 10

The Top 10 is an awareness document, not a standard. Use `find_sheets.py --top10 A0n` to show which guidance covers each category, labelled as the **2021** edition (the repo's index). Don't present Top 10 coverage as compliance.
