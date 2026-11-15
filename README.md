<div align="center">
  <img
    src="assets/stack-audit-readme-banner.png"
    alt="stack-audit: Engineering Standards, Read-Only Audits, and OWASP Security"
    width="100%"
  />
</div>

# stack-audit

A [Claude Code](https://claude.com/claude-code) plugin with engineering standards and **read-only** audits for React / Next.js apps, Docker / Compose stacks, and OWASP-backed security guidance.

It gives Claude three skills, each with written standards, audit scripts that scan a project in seconds, and ready-to-use templates.

| Skill | Covers | Use it for |
|---|---|---|
| `web-standards` | React / Next.js: rendering, performance, state, networking, caching, architecture, security, accessibility and i18n, git hygiene. 177 rules, tuned for Next.js 16 and React 19. | Reviewing a file or PR, planning a page's rendering and caching, a pre-launch audit |
| `container-standards` | Dockerfiles, Compose stacks, networks, published ports, secrets, volumes, Docker hosts, Coolify. 52 rules. | Reviewing a Dockerfile or Compose file, hardening a stack before deploy |
| `owasp-security` | The OWASP Cheat Sheet Series, ASVS 5.0 and the OWASP Top 10, from a local copy. | "What does OWASP recommend for X", citations for a security doc, an ASVS self-assessment |

## What you can ask

You don't need to name a skill. Ask normally and Claude loads the right one:

```text
review src/app/checkout/page.tsx before I open a PR
is compose.prod.yaml safe to deploy? read-only, don't change anything
what does OWASP recommend for password reset flows? I need the cheat sheet section
how do we stand against ASVS level 2? give me the gaps
audit this repo before launch: security, accessibility and the Docker setup
```

Or call a skill directly:

```text
/stack-audit:web-standards
/stack-audit:container-standards
/stack-audit:owasp-security
```

## Install

Requires Claude Code and Python 3.10 or later, available as `python` on your PATH. The scripts use the standard library only, so there is nothing to `pip install`. git is optional; with it, scans respect `.gitignore` and can check only changed files.

From inside Claude Code:

```text
/plugin marketplace add COVADigital/stack-audit
/plugin install stack-audit@stack-audit
```

On Claude Code 2.1.275 or later this also works in one step:

```text
/plugin install stack-audit --marketplace COVADigital/stack-audit
```

To try it without installing, clone the repository and start Claude Code with:

```sh
claude --plugin-dir path/to/stack-audit
```

### One-time setup for `owasp-security`

The OWASP skill reads a local clone of the cheat sheets. Nothing is downloaded when you install the plugin. The first time you ask an OWASP question without the clone, Claude tells you it's missing and offers to run the command below; it runs only if you agree. You can also clone it yourself beforehand:

```sh
git clone https://github.com/OWASP/CheatSheetSeries.git ~/.claude/data/owasp-cheatsheets
```

To keep it somewhere else, set `STACK_AUDIT_OWASP_CHEATSHEETS` to the path.

### Keeping the cheat sheets current

At the start of each session the plugin checks how long ago the clone was last updated. This is a local file check with no network access. If it has been more than 30 days, Claude tells you the next time an OWASP question comes up and offers to update it; it runs `git pull` only if you agree. The copy keeps working if you decline.

To update without being asked, turn on automatic updates. The plugin then pulls at session start, at most once every 30 days. It is off by default because it uses the network without asking first. Either set an environment variable:

```sh
STACK_AUDIT_OWASP_AUTO_UPDATE=1
```

or add this to `stack-audit.config.json` in a project:

```json
{ "owasp": { "autoUpdate": true } }
```

You can always update by hand with `git -C ~/.claude/data/owasp-cheatsheets pull --ff-only`.

## How it works

- **A start-up hook** tells Claude when to load each skill, so a question like "review this file" uses the standards instead of an answer from memory.
- **Each skill is a `SKILL.md`** with reference files Claude reads only when it needs them. Findings cite rule IDs such as `sec.16`, which map to a section in the references.
- **Audit scripts** do the mechanical scanning and report `file:line` findings with a severity, a fix hint and the rule ID.
- **Missing scanners are offered, never installed silently.** Some checks use outside tools (hadolint, trivy, grype, gitleaks). If one isn't installed, Claude asks whether to run it once from its official container image, install it system-wide, or skip that check.
- **Checks worth repeating can be saved.** When Claude runs a check of its own that you're likely to need again, it asks whether to keep it one-off, save it as a test in your project's existing test suite, or save it as a standalone script. Nothing is saved without your say-so.
- **`owasp-security` quotes from the local clone**, by sheet and section with a link, and has a checker that verifies every citation exists. ASVS results are always labelled as a self-assessment, never as compliance or certification.

### Safety

- The audit scripts never modify the project they scan and never install anything.
- They make no network calls unless you pass an explicit flag: `--url` (probe a deployed site's headers), `--audit` (npm audit), `--remote` (GitHub settings) or `--image` (image vulnerability scan).
- The start-up hook only reads local files, unless you have turned on automatic cheat sheet updates.
- The Compose audit never reads env files or secret files, and never prints secret values.
- Claude asks before running anything that contacts an external service.

## Use the audits without Claude

The scripts are plain command-line tools. They work in a terminal or CI, with no API usage:

```sh
# What stack is this project?
python scripts/stack_profile.py --root path/to/app

# All static web checks, or selected domains
python skills/web-standards/scripts/run_audit.py --root path/to/app --phase review
python skills/web-standards/scripts/run_audit.py --root path/to/app --domain sec,a11y

# Dockerfiles and Compose files
python skills/container-standards/scripts/run_audit.py --root path/to/repo --phase build

# OWASP: find the right sheet, read one section, check citations in a document
python skills/owasp-security/scripts/find_sheets.py "csrf server actions"
python skills/owasp-security/scripts/read_section.py --sheet Session_Management --list
python skills/owasp-security/scripts/verify_citations.py docs/security.md
```

Conventions shared by every audit script:

- Options: `--root`, `--changed [--base REF]`, `--format md|json|sarif`, `--out FILE`, `--strict`, `--config FILE`
- Exit codes: `0` ran (findings may exist) · `1` `--strict` and error findings remain · `2` usage or config error
- Findings: `rule` (for example `sec.16`), `severity` (error/warn/info), `confidence` (high/medium/low), `file:line`, `fix_hint`, `ref`, `owasp`

### Suppressing a finding

Inline, with a required reason:

```ts
// stack-audit-ignore sec.01 -- sanitized by DOMPurify in lib/html.ts
```

`#` and `{/* */}` comments work too, as do several rules (`sec.01,sec.14`) and a domain wildcard (`sec.*`). A suppression with no reason doesn't suppress anything and is reported as `meta.01`.

Per path, in `stack-audit.config.json` at the project root:

```json
{ "ignore": { "sec.01": ["src/legacy/**"] } }
```

## Templates

Each skill ships starting points Claude can adapt, in `skills/<name>/assets/`:

- **web-standards:** security headers for `next.config.ts`, a CSP proxy with nonces, `.gitignore`, Dependabot, pre-commit secret scanning, Lighthouse CI, an axe accessibility test, an ADR template.
- **container-standards:** Dockerfiles for Next.js standalone and for a Node service, a hardened Compose file, `.dockerignore`, `daemon.json` with log rotation, a CI image-scan workflow.

## What has been measured

Tested with Claude Opus 5.5:

- **Loading:** with the start-up hook, each skill loaded on every test question it should (8 of 8 per skill) and on none of the unrelated ones.
- **`owasp-security`:** answers passed 8 of 8 checks with the skill and 4 of 8 without. Without it, the model missed that OWASP has a webhook cheat sheet and quoted a requirement number from memory.
- **`web-standards` and `container-standards`:** answers passed every check with the skills, and the model alone also passed every check, including on a 63-file project and a 12-service stack. Their practical value is the audit scripts: fast, repeatable, and free to run.

The test cases are in `skills/<name>/evals/`.

## Repository layout

```text
.claude-plugin/              plugin and marketplace manifests
assets/                      banner, icon and social preview images
hooks/                       SessionStart hook: when to load each skill, cheat sheet setup and update checks
lib/wclib/                   shared Python library (stdlib only), used by all skills
scripts/                     shared CLIs (stack_profile.py)
skills/<name>/               SKILL.md, references/, scripts/, assets/, evals/
tests/                       unittest suite
```

Run the tests with:

```sh
python -m unittest discover -s tests -t tests
```

## License and attribution

MIT. See [LICENSE](LICENSE).

The standards are written in the plugin's own words. The `owasp-security` skill cites the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) (CC BY-SA 4.0) and reads it from your own clone; no OWASP text is bundled. This project is not affiliated with or endorsed by OWASP, Vercel, Docker or Anthropic.
