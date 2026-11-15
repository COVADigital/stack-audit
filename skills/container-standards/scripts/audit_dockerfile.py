#!/usr/bin/env python3
"""Dockerfile + .dockerignore audit (img.*, csec.03-06, sup.05). Read-only, static.

    python audit_dockerfile.py --root REPO [--format md|json|sarif] [--strict]
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import _bootstrap  # noqa: F401
from wclib.audit import Audit, run_main
from wclib.containers import DOCKERFILE_RE, is_secret_name
from wclib.dockerfile import Dockerfile, image_parts, parse
from wclib.walker import repo_paths

SECRET_FILES = re.compile(r"(^|/|\s)(\.env(\.[\w.-]+)?|[\w.-]*\.(pem|key|p12|pfx|jks|keystore)|id_(rsa|ed25519|ecdsa|dsa)|\.npmrc|\.pypirc|\.netrc|credentials(\.json)?|service-account[\w.-]*\.json)(\s|$)", re.I)
ARCHIVE = re.compile(r"\.(tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst)$", re.I)
INSTALLS = re.compile(r"\b(npm\s+(ci|install|i)\b|pnpm\s+install|yarn(\s+install)?\b|bun\s+install|pip\s+install|composer\s+install|go\s+build|cargo\s+build)")


class DockerfileAudit(Audit):
    tool = "audit_dockerfile"
    prefix = "img"
    exts: set[str] = set()

    def dockerfiles(self) -> list[str]:
        return [f for f in self.ctx.walker.all_files() if DOCKERFILE_RE.search(f) and "node_modules" not in f]

    def check(self, rel: str) -> None:
        text = self.read(rel)
        df = parse(text, rel)
        if not df.stages:
            return
        ctx_dir = str(PurePosixPath(rel).parent) if "/" in rel else ""
        stage_names = {s.name for s in df.stages if s.name}
        add = lambda rule, msg, line=None, **kw: self.add(rule, msg, file=rel, line=line, **kw)  # noqa: E731

        # img.01 base pinning
        unpinned_digest = []
        for st in df.stages:
            if st.base in stage_names or st.base.lower() == "scratch":
                continue
            if "${" in st.base or "$" in st.base:
                add("img.01", f"Base image `{st.base_raw}` comes from an ARG without a default", st.line, severity="info")
                continue
            name, tag, digest = image_parts(st.base)
            if not tag and not digest or tag == "latest":
                add("img.01", f"Base image `{st.base}` is unpinned ({'latest' if tag == 'latest' else 'no tag'})", st.line,
                    fix_hint="Pin a version tag, and a digest for production: image:1.2.3@sha256:…")
            elif not digest:
                unpinned_digest.append(st.base)
        if unpinned_digest and df.final_stage.base in unpinned_digest:
            add("img.01", f"Runtime base `{df.final_stage.base}` is tag-pinned but not digest-pinned", df.final_stage.line,
                severity="info", fix_hint="Append @sha256:<digest> and let Dependabot (docker ecosystem) update it")

        final = df.final()
        fidx = df.final_stage.index
        # img.02 non-root user
        users = [i for i in final if i.cmd == "USER"]
        base_nonroot = re.search(r"distroless.*nonroot|:nonroot|chainguard|cgr\.dev", df.final_stage.base, re.I)
        if not users and not base_nonroot:
            add("img.02", "Final stage has no USER: the container runs as root", df.final_stage.line,
                fix_hint="USER 1000:1000 (node images ship uid 1000 'node') after root-only steps")
        elif users and re.fullmatch(r"(root|0)(:(root|0))?", users[-1].body.strip()):
            add("img.02", "Final stage USER is root", users[-1].line)

        for ins in df.instructions:
            # img.03 ADD
            if ins.cmd == "ADD":
                srcs = ins.body.split()[:-1]
                for s in srcs:
                    if s.startswith(("http://", "https://")):
                        if "checksum" not in ins.flags:
                            add("img.03", f"ADD downloads {s} without --checksum", ins.line)
                    elif not ARCHIVE.search(s) and not s.startswith("git@"):
                        add("img.03", f"ADD used to copy local `{s}`: use COPY", ins.line, fix_hint="COPY for files and folders (DL3020)")
            # img.04 curl | sh
            if ins.cmd == "RUN" and re.search(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", ins.args + ins.heredoc):
                add("img.04", "RUN pipes a downloaded script straight into a shell", ins.line,
                    fix_hint="Download to a file, verify its checksum/signature, then run it")
            # img.05 package hygiene
            if ins.cmd == "RUN":
                body = ins.args + ins.heredoc
                if re.search(r"apt-get\s+(-\S+\s+)*install", body):
                    if "--no-install-recommends" not in body:
                        add("img.05", "apt-get install without --no-install-recommends", ins.line)
                    if "/var/lib/apt/lists" not in body:
                        add("img.05", "apt lists not removed in the same RUN (bigger layer)", ins.line)
                if re.search(r"\bapk\s+add\b", body) and "--no-cache" not in body:
                    add("img.05", "apk add without --no-cache", ins.line)
            # csec.04 secrets in ARG/ENV
            if ins.cmd in ("ARG", "ENV"):
                names = re.findall(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)(?==|\s|$)", ins.body) if ins.cmd == "ENV" else \
                    [ins.body.split("=", 1)[0].strip()]
                for n in names:
                    if is_secret_name(n):
                        add("csec.04", f"{ins.cmd} `{n}` looks like a secret: it persists in the image history", ins.line,
                            fix_hint="Use RUN --mount=type=secret at build time; inject runtime secrets via the environment")
                    if ins.cmd == "ARG" and n.startswith("NEXT_PUBLIC_"):
                        add("img.11", f"ARG `{n}` is baked into the client bundle at build time (one image per environment)",
                            ins.line, severity="info")
            # csec.05 copying secret files
            if ins.cmd in ("COPY", "ADD"):
                srcs = ins.body.split()[:-1] if not ins.exec_form else ins.exec_form[:-1]
                for s in srcs:
                    if SECRET_FILES.search(" " + s + " ") and not s.endswith((".example", ".sample", ".template")):
                        add("csec.05", f"{ins.cmd} copies secret-like file `{s}` into the image", ins.line,
                            fix_hint="Never copy credentials; use secret mounts. Deleting later doesn't remove the layer")
        # csec.05 COPY then rm
        copied = {}
        for ins in df.instructions:
            if ins.cmd == "COPY" and not ins.flags.get("from"):
                parts = ins.body.split()
                if len(parts) == 2:
                    copied[PurePosixPath(parts[1]).name or PurePosixPath(parts[0]).name] = ins
            if ins.cmd == "RUN":
                for name, c in copied.items():
                    if re.search(rf"\brm\s+(-\w+\s+)*\S*{re.escape(name)}\b", ins.args) and SECRET_FILES.search(" " + name + " "):
                        add("csec.05", f"`{name}` is copied (line {c.line}) and deleted later: it remains in the earlier layer", ins.line)

        # img.06 exec form
        for ins in final:
            if ins.cmd in ("CMD", "ENTRYPOINT") and ins.exec_form is None and ins.body.strip():
                add("img.06", f"{ins.cmd} uses shell form (SIGTERM is not forwarded to the process)", ins.line,
                    fix_hint='CMD ["node", "server.js"] (and init: true in Compose)')
        # img.07 healthcheck
        if not df.find("HEALTHCHECK", fidx):
            add("img.07", "No HEALTHCHECK in the final stage (fine if Compose defines one)", df.final_stage.line)
        # img.08 multi-stage for builds
        has_install = any(INSTALLS.search(i.args) for i in df.find("RUN"))
        if len(df.stages) == 1 and has_install:
            add("img.08", "Single-stage build installs dependencies: build tools and dev deps ship in the image",
                df.stages[0].line, fix_hint="Use deps/build stages and copy only the output into a minimal runtime stage")
        # img.09 install hygiene
        for st in df.stages:
            ins_list = df.in_stage(st.index)
            install_idx = next((k for k, i in enumerate(ins_list) if i.cmd == "RUN" and INSTALLS.search(i.args)), None)
            copy_all = next((k for k, i in enumerate(ins_list) if i.cmd == "COPY" and re.fullmatch(r"\.\s+\S+", i.body.strip())
                             and not i.flags.get("from")), None)
            if install_idx is not None and copy_all is not None and copy_all < install_idx:
                add("img.09", "COPY . . before installing dependencies (every source change re-installs)", ins_list[copy_all].line,
                    fix_hint="COPY the lockfile first, install, then COPY the rest")
            for i in ins_list:
                if i.cmd == "RUN" and re.search(r"\bnpm\s+(install|i)\b(?!\s+-g)", i.args):
                    add("img.09", "npm install in an image (not reproducible): use npm ci", i.line)
        # img.10 CRLF
        if df.crlf:
            add("img.10", "Dockerfile has CRLF line endings", 1, fix_hint=".gitattributes: Dockerfile text eol=lf")
        ctx_path = self.root / ctx_dir if ctx_dir else self.root
        for sh in sorted(ctx_path.glob("**/*.sh")):
            if "node_modules" in sh.parts:
                continue
            try:
                if b"\r\n" in sh.read_bytes()[:100_000]:
                    add("img.10", f"Shell script {sh.relative_to(self.root).as_posix()} has CRLF endings (breaks in Linux containers)",
                        fix_hint="*.sh text eol=lf in .gitattributes, then renormalize")
            except OSError:
                pass
        # img.11 Next.js standalone
        pkg = ctx_path / "package.json"
        if pkg.exists() and '"next"' in pkg.read_text(encoding="utf-8", errors="replace"):
            copies_next = any(".next" in i.args for i in df.find("COPY"))
            nconf = next((p for p in ctx_path.glob("next.config.*")), None)
            standalone = nconf and re.search(r"output\s*:\s*['\"]standalone['\"]", nconf.read_text(encoding="utf-8", errors="replace"))
            if copies_next and not standalone:
                add("img.11", "Next.js image without output: 'standalone' (ships all of node_modules)", severity="info")
            env_text = " ".join(i.args for i in final if i.cmd == "ENV")
            if standalone and "server.js" in " ".join(i.args for i in final if i.cmd in ("CMD", "ENTRYPOINT")) and "HOSTNAME" not in env_text:
                add("img.11", "Standalone server without HOSTNAME=0.0.0.0 may only listen inside the container's loopback",
                    severity="info")
        self.dockerignore(ctx_path, ctx_dir)

    def dockerignore(self, ctx_path: Path, ctx_dir: str) -> None:
        di = ctx_path / ".dockerignore"
        rel = (ctx_dir + "/.dockerignore").lstrip("/")
        if not di.exists():
            self.add("csec.06", f"No .dockerignore in build context `{ctx_dir or '.'}`: COPY . . can include .env and .git",
                     file=rel, severity="error", fix_hint="Copy assets/dockerignore.node")
            return
        lines = [l.strip() for l in di.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip() and not l.startswith("#")]
        def covers(pats):  # noqa: E306
            return any(re.fullmatch(p, l.lstrip("/").rstrip("/")) for p in pats for l in lines)
        if not covers([r"\.env\*?", r"\.env\.?\*", r"\*\*/\.env\*?", r"\*\.env", r"\.env.*"]):
            self.add("csec.06", ".dockerignore does not exclude .env files", file=rel, severity="error")
        missing = [label for label, pats in ((".git", [r"\.git", r"\*\*/\.git"]), ("node_modules", [r"node_modules", r"\*\*/node_modules"]))
                   if not covers(pats)]
        if missing:
            self.add("csec.06", f".dockerignore does not exclude {', '.join(missing)}", file=rel)

    def run(self) -> None:
        files = self.dockerfiles()
        if not files:
            self.report.skipped.append("No Dockerfiles found")
        for rel in files:
            self.check(rel)
        if files:
            dep = next((b / p for b in repo_paths(self.root) for p in (".github/dependabot.yml", ".github/dependabot.yaml") if (b / p).exists()), None)
            renovate = any((b / p).exists() for b in repo_paths(self.root) for p in ("renovate.json", ".github/renovate.json", "renovate.json5"))
            if not renovate and (not dep or "docker" not in dep.read_text(encoding="utf-8", errors="replace")):
                self.add("sup.05", "No automated base-image updates (Dependabot `docker` ecosystem / Renovate)", severity="info",
                         fix_hint="Add a docker entry to .github/dependabot.yml (pinned digests don't update themselves)")
        self.report.meta["dockerfiles"] = files
        self.report.not_checked += [n for p in ("img", "csec") for n in self.rb.not_checked(p)]
        self.report.not_checked.append("`sup.02` full hadolint rule set: run scan_image.py --dockerfile (needs hadolint)")


if __name__ == "__main__":
    run_main(DockerfileAudit, __file__, __doc__)
