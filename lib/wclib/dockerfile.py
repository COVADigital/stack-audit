"""Dockerfile parser: instructions with line numbers, stages, ARG resolution (stdlib only)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class Instruction:
    cmd: str            # upper-case: FROM, RUN, COPY, ...
    args: str           # raw arguments (continuations joined with spaces)
    line: int           # 1-based line of the instruction start
    stage: int          # index into Dockerfile.stages
    flags: dict[str, str] = field(default_factory=dict)   # --from=build, --chown=..., --mount=...
    heredoc: str = ""

    @property
    def exec_form(self) -> list[str] | None:
        body = self.body.strip()
        if body.startswith("["):
            try:
                val = json.loads(body)
                return val if isinstance(val, list) else None
            except json.JSONDecodeError:
                return None
        return None

    @property
    def body(self) -> str:
        """Arguments with leading --flags removed."""
        return re.sub(r"^(?:\s*--[\w-]+(?:=(?:\"[^\"]*\"|\S+))?)+\s*", "", self.args)


@dataclass
class Stage:
    index: int
    base: str           # FROM image after ARG resolution
    base_raw: str
    name: str | None
    line: int
    platform: str | None = None


@dataclass
class Dockerfile:
    path: str
    instructions: list[Instruction]
    stages: list[Stage]
    global_args: dict[str, str]
    crlf: bool = False
    escape: str = "\\"

    def in_stage(self, idx: int) -> list[Instruction]:
        return [i for i in self.instructions if i.stage == idx]

    @property
    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None

    def final(self) -> list[Instruction]:
        return self.in_stage(self.final_stage.index) if self.stages else []

    def find(self, cmd: str, stage: int | None = None) -> list[Instruction]:
        return [i for i in self.instructions if i.cmd == cmd and (stage is None or i.stage == stage)]


def _expand(value: str, args: dict[str, str]) -> str:
    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(3)
        default = m.group(2)
        if name in args and args[name] != "":
            return args[name]
        return default if default is not None else m.group(0)
    return re.sub(r"\$\{(\w+)(?::-([^}]*))?\}|\$(\w+)", repl, value)


def parse(text: str, path: str = "Dockerfile") -> Dockerfile:
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    escape = "\\"
    for line in lines[:5]:
        m = re.match(r"#\s*escape\s*=\s*(\S)", line, re.I)
        if m:
            escape = m.group(1)
    instructions: list[Instruction] = []
    stages: list[Stage] = []
    global_args: dict[str, str] = {}
    stage_args: dict[str, str] = {}
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        parts = [stripped]
        while parts[-1].endswith(escape) and i + 1 < len(lines):
            parts[-1] = parts[-1][:-1].rstrip()
            i += 1
            nxt = lines[i].strip()
            while nxt.startswith("#") and i + 1 < len(lines):  # comments inside continuations are dropped
                i += 1
                nxt = lines[i].strip()
            parts.append(nxt)
        joined = " ".join(p for p in parts if p)
        m = re.match(r"(\w+)\s*(.*)$", joined, re.S)
        if not m:
            i += 1
            continue
        cmd, args = m.group(1).upper(), m.group(2)
        heredoc = ""
        hd = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", args)
        if hd and cmd in ("RUN", "COPY"):
            end_tag, body = hd.group(1), []
            while i + 1 < len(lines):
                i += 1
                if lines[i].strip() == end_tag:
                    break
                body.append(lines[i])
            heredoc = "\n".join(body)
        flags = {}
        rest = args
        while True:
            fm = re.match(r"\s*--([\w-]+)(?:=(\"[^\"]*\"|\S+))?", rest)
            if not fm:
                break
            flags.setdefault(fm.group(1), fm.group(2) or "")
            if fm.group(1) == "mount":
                flags.setdefault("mounts", "")
                flags["mounts"] = (flags["mounts"] + " " + (fm.group(2) or "")).strip()
            rest = rest[fm.end():]
        if cmd == "ARG":
            am = re.match(r"(\w+)(?:=(.*))?$", args.strip())
            if am:
                val = (am.group(2) or "").strip().strip('"').strip("'")
                if not stages:
                    global_args[am.group(1)] = val
                else:
                    stage_args[am.group(1)] = val if val else global_args.get(am.group(1), "")
        if cmd == "FROM":
            fm = re.match(r"(?:--platform=(\S+)\s+)?(\S+)(?:\s+AS\s+(\S+))?", args.strip(), re.I)
            base_raw = fm.group(2) if fm else args.strip()
            base = _expand(base_raw, global_args)
            stages.append(Stage(len(stages), base, base_raw, fm.group(3) if fm else None, start, fm.group(1) if fm else None))
            stage_args = {}
        instructions.append(Instruction(cmd, args, start, len(stages) - 1, flags, heredoc))
        i += 1
    return Dockerfile(path, instructions, stages, global_args, crlf, escape)


def image_parts(ref: str) -> tuple[str, str | None, str | None]:
    """'node:24-alpine@sha256:abc' -> ('node', '24-alpine', 'sha256:abc')."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    name, tag = ref, None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
    return name, tag, digest
