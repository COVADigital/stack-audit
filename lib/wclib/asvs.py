"""OWASP ASVS 5.0 requirements: locate, verify and load the release JSON. Read-only, offline.

The requirement text (CC BY-SA 4.0) is never bundled with the plugin. The user downloads OWASP's
release file once, with consent, into ~/.claude/data/owasp-asvs/. This module never fetches
anything: it finds the file, checks it against a pinned SHA-256 and indexes it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

VERSION = "5.0.0"
RELEASE_TAG = "v5.0.0_release"
DOWNLOAD_URL = ("https://github.com/OWASP/ASVS/releases/download/v5.0.0_release/"
                "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json")
SHA256 = "8201b20eec2908c3380ac600c91c8ba746346fbb808859366abb232027532311"
DEFAULT_PATH = Path.home() / ".claude" / "data" / "owasp-asvs" / f"asvs-{VERSION}.flat.json"
SOURCE_BASE = f"https://github.com/OWASP/ASVS/blob/{RELEASE_TAG}/5.0/en/"
ATTRIBUTION = f"OWASP Application Security Verification Standard {VERSION}, CC BY-SA 4.0"

# Chapter -> file in OWASP's repo, for citation links (file names only, no licensed text).
CHAPTER_FILES = {
    "V1": "0x10-V1-Encoding-and-Sanitization.md", "V2": "0x11-V2-Validation-and-Business-Logic.md",
    "V3": "0x12-V3-Web-Frontend-Security.md", "V4": "0x13-V4-API-and-Web-Service.md",
    "V5": "0x14-V5-File-Handling.md", "V6": "0x15-V6-Authentication.md", "V7": "0x16-V7-Session-Management.md",
    "V8": "0x17-V8-Authorization.md", "V9": "0x18-V9-Self-contained-Tokens.md", "V10": "0x19-V10-OAuth-and-OIDC.md",
    "V11": "0x20-V11-Cryptography.md", "V12": "0x21-V12-Secure-Communication.md", "V13": "0x22-V13-Configuration.md",
    "V14": "0x23-V14-Data-Protection.md", "V15": "0x24-V15-Secure-Coding-and-Architecture.md",
    "V16": "0x25-V16-Security-Logging-and-Error-Handling.md", "V17": "0x26-V17-WebRTC.md",
}

# Uppercase "V" and no zero parts: "ASVS v4.0.3" or "V5.0.0" are versions, not requirement references.
REQ_REF = re.compile(r"(?<![\w.])V([1-9]\d?)\.([1-9]\d?)\.([1-9]\d?)(?![\w]|\.\d)")
SECTION_REF = re.compile(r"(?<![\w.])V([1-9]\d?)\.([1-9]\d?)(?![\w]|\.\d)")


class AsvsError(RuntimeError):
    pass


def download_command(path: Path = DEFAULT_PATH) -> str:
    return f'curl -fsSL --create-dirs -o "{Path(path).as_posix()}" "{DOWNLOAD_URL}"'


def expected_sha256() -> str:
    # Override only to test or to accept a newer release before the plugin pins it.
    return os.environ.get("STACK_AUDIT_OWASP_ASVS_SHA256", "").strip().lower() or SHA256


def resolve_path(explicit: str | Path | None = None, config: dict | None = None) -> Path:
    """Find the release JSON: explicit > $STACK_AUDIT_OWASP_ASVS > config owasp.asvsPath > default."""
    candidates = [explicit, os.environ.get("STACK_AUDIT_OWASP_ASVS"),
                  ((config or {}).get("owasp") or {}).get("asvsPath"), DEFAULT_PATH]
    tried = []
    for c in candidates:
        if not c:
            continue
        p = Path(c).expanduser().resolve()
        tried.append(str(p))
        if p.is_file():
            return p
    raise AsvsError(f"ASVS {VERSION} requirement data not found. Tried: {', '.join(tried)}. "
                    f"Download it (163 KB, from OWASP's GitHub release) with: {download_command()}")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path: Path) -> dict:
    """Verify and index the release JSON. Raises AsvsError on a hash mismatch or bad format."""
    path = Path(path)
    digest = file_sha256(path)
    if digest != expected_sha256():
        raise AsvsError(f"{path} does not match the pinned SHA-256 for ASVS {VERSION} (got {digest[:12]}…): "
                        f"wrong version, incomplete or modified. Download it again with: {download_command(path)}")
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))["requirements"]
        reqs, sections = {}, {}
        for r in rows:
            req = {"id": r["req_id"], "level": int(r["L"]), "text": r["req_description"].strip(),
                   "section_id": r["section_id"], "section_name": r["section_name"],
                   "chapter_id": r["chapter_id"], "chapter_name": r["chapter_name"]}
            reqs[req["id"]] = req
            sec = sections.setdefault(req["section_id"], {"id": req["section_id"], "name": req["section_name"],
                                                          "chapter_id": req["chapter_id"],
                                                          "chapter_name": req["chapter_name"], "requirements": []})
            sec["requirements"].append(req["id"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AsvsError(f"{path} is not the ASVS flat JSON format: {exc}") from exc
    return {"version": VERSION, "path": str(path), "sha256": digest, "requirements": reqs, "sections": sections}


def try_load(explicit: str | Path | None = None, config: dict | None = None) -> tuple[dict | None, str | None]:
    """(data, None) when available and verified, else (None, reason) for a fallback message."""
    try:
        return load(resolve_path(explicit, config)), None
    except AsvsError as exc:
        return None, str(exc)


def github_anchor(heading: str) -> str:
    """GitHub's heading slug: lowercase, drop punctuation except - and _, spaces to hyphens."""
    return re.sub(r"[^a-z0-9 _-]", "", heading.lower()).replace(" ", "-")


def cite_url(data: dict, item_id: str) -> str:
    """Link to the requirement's (or section's) section in OWASP's markdown at the release tag."""
    req = data["requirements"].get(item_id)
    sec = data["sections"][req["section_id"] if req else item_id]
    return f"{SOURCE_BASE}{CHAPTER_FILES[sec['chapter_id']]}#{github_anchor(sec['id'] + ' ' + sec['name'])}"


def in_level(data: dict, ids: list[str], level: int | None) -> list[str]:
    return [i for i in ids if level is None or data["requirements"][i]["level"] <= level]


def refs_in_text(text: str) -> list[tuple[int, str, str]]:
    """(line, kind, id) for each ASVS requirement ("req") or section ("section") reference."""
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        out += [(n, "req", "V" + ".".join(m.groups())) for m in REQ_REF.finditer(line)]
        out += [(n, "section", "V" + ".".join(m.groups())) for m in SECTION_REF.finditer(line)]
    return out
