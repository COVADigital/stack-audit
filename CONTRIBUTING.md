# Contributing to stack-audit

Thanks for your interest. Bug reports, false-positive reports and pull requests are all welcome.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are accepted under the project's [MIT license](LICENSE).

## Reporting a problem

- **A security vulnerability in the plugin:** don't open an issue. Follow [SECURITY.md](SECURITY.md).
- **A false positive or a missed finding:** open an issue with the rule ID (for example `sec.06`), the smallest code or config snippet that shows it, and what you expected.
- **Anything else:** open an issue with the command you ran, the output, your operating system and your Python version.

Please remove real secrets, hostnames and private code from anything you post.

## Setting up

You need Python 3.10 or later. There are no packages to install: everything uses the standard library. git is needed for some tests.

```sh
git clone https://github.com/COVADigital/stack-audit.git
cd stack-audit
python -m unittest discover -s tests -t tests
```

To try your changes in Claude Code:

```sh
claude --plugin-dir path/to/stack-audit
claude plugin validate path/to/stack-audit
```

The `owasp-security` tests and scripts need a local clone of the OWASP Cheat Sheet Series. See "One-time setup" in the [README](README.md).

## Ground rules for changes

These are what make the plugin safe to run on someone else's project, so pull requests that break them won't be merged:

- **Read-only.** Audit scripts never modify the project they scan and never install anything.
- **No network by default.** Anything that contacts a service must sit behind an explicit flag or setting, and the skill must tell Claude to ask first.
- **No secret values.** Never read env or secret files, and never print a secret value. Report names only.
- **Standard library only.** No third-party Python packages.
- **Your own words.** Don't copy text from the OWASP Cheat Sheet Series (CC BY-SA 4.0) or other sources into the skills. Describe the rule yourself and cite the sheet.
- **No personal or private project details** in code, fixtures or examples.

## Adding or changing a rule

Each rule has an ID such as `sec.06`: a domain prefix plus the section number in that domain's reference file.

1. Describe the rule in the matching file under `skills/<skill>/references/`.
2. Add or update its entry in `skills/<skill>/rules.json` (how it's checked, default severity, related OWASP sheets).
3. Regenerate the index: `python skills/<skill>/scripts/build_rule_index.py`.
4. If the rule can be checked automatically, add the check to the matching `audit_*.py` script. Give each finding a rule ID, a severity, a confidence, a `file:line` and a fix hint.
5. Add a test under `tests/` that shows the check firing on a bad example and staying quiet on a good one.

## Pull requests

- Keep each pull request to one change.
- Make sure `python -m unittest discover -s tests -t tests` and `claude plugin validate .` both pass.
- Say what you changed and how you tested it. For a new or changed check, include an example it catches.
- Update the README or the skill's `SKILL.md` if behaviour that users see has changed.

This project is maintained by one person, so reviews may take a little while.
