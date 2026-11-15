# Security Policy

## What stack-audit is and isn't

stack-audit gives engineering guidance, read-only audits and OWASP-based self-assessments. It is not a security certification, and it does not guarantee that it will find every vulnerability in a project. A clean report means the checks it ran found nothing; it does not mean the project is secure.

## Supported versions

Security fixes are made on the latest release only.

## Reporting a vulnerability in stack-audit

Please do not open a public issue for a security problem.

Report it privately in one of these ways:

1. **GitHub private vulnerability reporting (preferred).** On this repository, open the **Security** tab and choose **Report a vulnerability**.
2. **Email** security@covadigital.io.

Please include:

- What the problem is and what an attacker could do with it.
- The steps or a small example that reproduces it.
- The plugin version (from `.claude-plugin/plugin.json`), your operating system and your Python version.

This project is maintained by one person. I aim to acknowledge a report within 7 days and will keep you updated while it is being fixed. Please give me a reasonable chance to release a fix before you disclose the problem publicly. I'm glad to credit you in the release notes if you would like.

## What counts

In scope, for example:

- A script or hook that changes files in the project it scans, or runs a command it shouldn't.
- Network access without the explicit flag or setting that is supposed to enable it.
- A script reading or printing secret values (env files, secret files, tokens).
- A crafted file in a scanned project that makes a script execute code or read files outside that project.
- Instructions in a skill that lead the agent (Claude Code or Codex) to take a harmful action.

Out of scope:

- Vulnerabilities in a project you scanned with stack-audit. Report those to that project.
- Vulnerabilities in third-party tools the plugin can call (npm, trivy, grype, hadolint, gitleaks) or in Claude Code or Codex themselves. Report those to their maintainers.
- Errors in the OWASP Cheat Sheet Series. Report those to [OWASP](https://github.com/OWASP/CheatSheetSeries).
- A missed finding or a false positive in an audit rule. That is a bug, not a vulnerability: please open a normal issue.
