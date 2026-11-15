# Git Security — 12 Habits

> **Applies to:** Next.js 16.x · React 19.2+ · Zod 4 · Tailwind CSS 4 · Drizzle · Better Auth. Other libraries follow the same patterns.  
> **Rule IDs:** section `NN` in this file is rule `git.NN` in audit findings.  
> **Verified:** 2026-11-13 against current docs (context7 / official sources).

> **Agent directive:** Apply these habits whenever you initialize a repo, set up CI, add collaborators, or commit code. Treat any violation as a blocking issue, not a suggestion.

---

## 01. Signed Commits
**What:** Cryptographically sign your commits with GPG or SSH so the host can verify you actually wrote them.
**Why:** Anyone can set `git config user.email` to your address. A signature proves who wrote the commit.

```bash
# SSH signing (simplest, Git 2.34+)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Verify
git log --show-signature -1
```
**Rule:** Enable `commit.gpgsign`. Upload the signing key to GitHub as a *Signing Key* (that's separate from the auth key).

---

## 02. Protected Main
**What:** Branch protection rules that block direct pushes and force pushes to `main`.
**Why:** One bad `git push --force` can rewrite history or ship untested code straight to production.

```bash
# GitHub CLI: create a ruleset that protects main
gh api repos/{owner}/{repo}/rulesets -X POST --input - <<'EOF'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_signatures" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true } }
  ]
}
EOF
```
**Rule:** All work goes through a feature branch and a pull request. Never push to `main`.

---

## 03. Required Reviews
**What:** Every merge needs approval from at least one other person (or one other checker).
**Why:** A second set of eyes catches leaked secrets, logic bugs, and malicious changes.

```text
# .github/CODEOWNERS
*                 @your-handle
/app/api/         @your-handle @your-org/security
/.github/         @your-handle
```
**Rule:** On a solo project, make a separate AI or CI review pass a required status check. Don't self-approve blindly.

---

## 04. .gitignore First
**What:** Create `.gitignore` *before* the first commit so that secrets and build output are never staged.
**Why:** Once a secret is committed it lives in history forever, even if you delete it in a later commit.

```gitignore
# Secrets
.env
.env.*
!.env.example
*.pem
*.key
id_rsa*

# Build / deps
node_modules/
.next/
dist/
coverage/

# OS / editor
.DS_Store
.vscode/*
!.vscode/extensions.json
```
**Rule:** `git init` → write `.gitignore` → *then* `git add`. Commit a `.env.example` with placeholder values only.

---

## 05. Pre-commit Scan
**What:** A hook that scans staged changes for secrets before the commit is created.
**Why:** Catching a key locally costs nothing. Catching it after the push means rotating credentials.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.x.y   # pin to the latest gitleaks release tag
    hooks:
      - id: gitleaks   # runs `gitleaks git --pre-commit --redact --staged`
```
```bash
pip install pre-commit && pre-commit install
# or with Husky (Node projects)
# gitleaks is a Go binary (not an npm package): install it first, then
npx husky init && echo "gitleaks git --pre-commit --redact --staged --verbose" > .husky/pre-commit
# `gitleaks protect` / `gitleaks detect` are deprecated since v8.19 — use `gitleaks git` / `gitleaks dir`
```
**Rule:** Install the hook on every new repo. Run the same scanner in CI as a backstop, and enable GitHub **push protection** for secret scanning so leaked keys are blocked server-side.

---

## 06. SSH Keys
**What:** Authenticate to the git host with per-device SSH keys instead of a password.
**Why:** You can revoke a key for one lost laptop without touching anything else.

```bash
ssh-keygen -t ed25519 -C "you@laptop-2026" -f ~/.ssh/id_ed25519_github
ssh-add ~/.ssh/id_ed25519_github
gh ssh-key add ~/.ssh/id_ed25519_github.pub --title "laptop-2026"
ssh -T git@github.com
```
**Rule:** Use one key per device, with a passphrase. Label each key with its device name and remove keys you no longer use.

---

## 07. 2FA on the Host
**What:** Two-factor authentication on GitHub, GitLab, npm, Vercel, and similar hosts.
**Why:** A stolen password alone can't get anyone in.

**Example checklist:**
- [ ] GitHub → Settings → Password and authentication → enable a passkey or TOTP
- [ ] Save recovery codes offline
- [ ] For organizations, require 2FA under Org settings → Authentication security
- [ ] Enable 2FA on npm: `npm profile enable-2fa auth-and-writes`
- [ ] For packages you publish: prefer npm **trusted publishing** (OIDC from CI) and `--provenance` over long-lived tokens

**Rule:** Prefer hardware keys or passkeys over SMS.

---

## 08. Scoped Tokens
**What:** Fine-grained personal access tokens that only reach the repos and permissions they need, and that expire.
**Why:** A leaked token that can "write everything" is a disaster. A leaked "read one repo" token is an annoyance.

```text
GitHub → Settings → Developer settings → Fine-grained tokens
  Repository access: Only select repositories → your-repo
  Permissions:       Contents: Read-only
  Expiration:        30 days
```
```yaml
# In GitHub Actions, lock down the default GITHUB_TOKEN
permissions:
  contents: read
```
**Rule:** Grant the least privilege, give every token an expiry, and use one token per purpose. Never use classic `repo`-scope tokens.

---

## 09. Automated Updates
**What:** Bots that open pull requests to bump vulnerable or outdated dependencies.
**Why:** Most breaches come through known CVEs in old packages.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "weekly" }
    groups:
      minor-and-patch:
        update-types: ["minor", "patch"]
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly" }
```
**Rule:** Turn on Dependabot alerts and security updates. Pin GitHub Actions to a commit SHA.

---

## 10. Branch Cleanup
**What:** Delete merged and stale branches.
**Why:** Old branches can hold old secrets, old vulnerable code, and confusing history.

```bash
# Auto-delete head branches after merge
gh repo edit --delete-branch-on-merge

# Prune locally
git fetch --prune
git branch --merged main | grep -v ' main$' | xargs -r git branch -d
```
**Rule:** Turn on "Automatically delete head branches". Review branches older than 90 days.

---

## 11. Masked CI Secrets
**What:** Keep secrets in the CI secret store and make sure they never appear in logs.
**Why:** Build logs are often visible to everyone with repo access, and sometimes to the public.

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production        # gated secrets
    steps:
      - uses: actions/checkout@<sha>
      - run: ./deploy.sh
        env:
          STRIPE_KEY: ${{ secrets.STRIPE_KEY }}   # auto-masked as ***
      # ❌ Never: run: echo $STRIPE_KEY
      # ❌ Never: set -x in scripts that touch secrets
```
**Rule:** Use environment-scoped secrets, and prefer OIDC to cloud providers over long-lived keys. Mask derived values with `::add-mask::`.

---

## 12. Access Reviews
**What:** Periodically audit who has access to repos, organizations, deploy keys, and integrations.
**Why:** Former teammates and forgotten OAuth apps are open doors.

```bash
gh api repos/{owner}/{repo}/collaborators --jq '.[].login'
gh api repos/{owner}/{repo}/keys --jq '.[] | {title, created_at}'
gh api orgs/{org}/members --jq '.[].login'
```
**Rule:** Run an access review every quarter and remove access the same day someone leaves.

---

### Quick audit checklist
| # | Habit | Done? |
|---|---|---|
| 01 | Signed commits | ☐ |
| 02 | Protected main | ☐ |
| 03 | Required reviews | ☐ |
| 04 | .gitignore first | ☐ |
| 05 | Pre-commit scan | ☐ |
| 06 | SSH keys | ☐ |
| 07 | 2FA on host | ☐ |
| 08 | Scoped tokens | ☐ |
| 09 | Automated updates | ☐ |
| 10 | Branch cleanup | ☐ |
| 11 | Masked CI secrets | ☐ |
| 12 | Access reviews | ☐ |

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 02, 03, 10 | Software_Supply_Chain_Security |
| 04, 05, 11 | Secrets_Management |
| 08, 09, 11 | GitHub_Actions_Security, CI_CD_Security |
| 09 | Vulnerable_Dependency_Management, Dependency_Graph_SBOM |
