# Supply Chain — 5 Practices

> **Applies to:** Image builds in CI and registries.  
> **Rule IDs:** section `NN` in this file is rule `sup.NN` in audit findings.  
> **Sources:** OWASP Docker Security cheat sheet (rules #9 and #13), OWASP Software Supply Chain Security and Dependency Graph/SBOM cheat sheets, Docker build attestation docs. Written in our own words.

---

## 01. Scan Images for Vulnerabilities and Secrets
**What:** Trivy, Grype or Docker Scout on every built image. Trivy also finds embedded secrets and misconfigurations.
**Why:** Base images and OS packages accumulate CVEs between your releases.

```bash
trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:sha
```
**Rule:** Scan images in CI and fail on fixable high or critical findings. Re-scan deployed images on a schedule, since new CVEs appear after release.

---

## 02. Lint Dockerfiles in CI
**What:** `hadolint` (an AST-based Dockerfile linter that also runs ShellCheck on `RUN`).
**Why:** It catches pinning, user, ADD and shell-form mistakes before review.

**Rule:** Run hadolint in CI. `audit_dockerfile.py` covers the security-relevant subset locally without installing anything.

---

## 03. SBOM and Provenance Attestations
**What:** `docker buildx build --sbom=true --provenance=mode=max`.
**Why:** You can answer "are we affected by CVE-X?" from the SBOM, and prove where an image came from.

**Rule:** Generate an SBOM and provenance for images you publish or deploy from a registry.

---

## 04. Sign Images and Use a Trusted Registry
**What:** Sigstore cosign or Notation signatures, verified at deploy, and a private registry with access control.
**Why:** It ensures the image you run is the image you built.

**Rule:** Sign release images and verify signatures before deploying. Restrict registry push access to CI.

---

## 05. Keep Base Images Updated
**What:** Dependabot's `docker` ecosystem (or Renovate) for `FROM` lines and Compose `image:` references.
**Why:** Digest-pinned images don't update themselves.

**Rule:** Enable automated update PRs for Dockerfiles and Compose images, and rebuild images at least monthly.

---

## OWASP mapping

| § | OWASP cheat sheet(s) |
|---|---|
| 01, 02 | Docker_Security |
| 03 | Dependency_Graph_SBOM, Software_Supply_Chain_Security |
| 04 | Software_Supply_Chain_Security |
| 05 | Vulnerable_Dependency_Management |
