"""Tests for the container-standards skill: parsers, audits, templates, content."""

import json
import re
import shutil
import subprocess
import sys
import unittest

from helpers import PLUGIN_ROOT, TempRepo
from wclib.containers import classify, is_secret_name, parse_port
from wclib.dockerfile import image_parts, parse
from wclib.findings import Report
from wclib.rules import RuleBook
from wclib.yamlish import YamlError, load

SKILL = PLUGIN_ROOT / "skills" / "container-standards"
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))


class YamlTests(unittest.TestCase):
    def test_anchors_merge_flow_quotes(self):
        text = """
x-h: &h
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
x-pw: &pw "${PW:?}"
services:
  app:
    image: "app:1"   # comment
    environment:
      A: *pw
      B: 'it''s'
      C: "say \\"hi\\""
    <<: *h
    cap_drop: [NET_RAW]
    networks: [backend, edge]
    labels: {a: b, "c": 'd'}
    command: >
      node
      server.js
  db:
    ports:
      - "127.0.0.1:5432:5432"
      - target: 80
        published: 8080
volumes:
  pgdata:
"""
        d, lines = load(text)
        app = d["services"]["app"]
        self.assertEqual(app["environment"], {"A": "${PW:?}", "B": "it's", "C": 'say "hi"'})
        self.assertTrue(app["read_only"])
        self.assertEqual(app["cap_drop"], ["NET_RAW"])  # explicit key wins over merge
        self.assertEqual(app["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(app["labels"], {"a": "b", "c": "d"})
        self.assertEqual(app["command"].strip(), "node server.js")
        self.assertEqual(d["services"]["db"]["ports"][1], {"target": 80, "published": 8080})
        self.assertIsNone(d["volumes"]["pgdata"])
        self.assertEqual(lines[("services", "app")], 8)
        self.assertEqual(lines[("services", "db", "ports", 0)], 23)

    def test_errors(self):
        with self.assertRaises(YamlError):
            load("a: *missing\n")


class DockerfileParserTests(unittest.TestCase):
    def test_parse(self):
        df = parse("""# syntax=docker/dockerfile:1
ARG BASE=node:24-alpine@sha256:abc
FROM ${BASE} AS deps
RUN --mount=type=secret,id=t,env=T npm ci \\
    && echo done
FROM deps AS build
COPY --from=deps --chown=1000:1000 /a /b
FROM ${BASE}
USER 1000
CMD ["node", "server.js"]
""")
        self.assertEqual([s.name for s in df.stages], ["deps", "build", None])
        self.assertEqual(df.stages[0].base, "node:24-alpine@sha256:abc")
        run = df.find("RUN")[0]
        self.assertIn("type=secret", run.flags["mount"])
        self.assertIn("echo done", run.args)
        self.assertEqual(run.line, 4)
        self.assertEqual(df.find("COPY")[0].flags["from"], "deps")
        self.assertEqual(df.find("CMD")[0].exec_form, ["node", "server.js"])
        self.assertEqual(image_parts("ghcr.io/o/app:1.2@sha256:x"), ("ghcr.io/o/app", "1.2", "sha256:x"))
        self.assertEqual(image_parts("localhost:5000/app"), ("localhost:5000/app", None, None))


class HelperTests(unittest.TestCase):
    def test_ports(self):
        self.assertTrue(parse_port("5432:5432").all_interfaces)
        self.assertTrue(parse_port("5432").all_interfaces)
        self.assertTrue(parse_port("0.0.0.0:80:80").all_interfaces)
        self.assertTrue(parse_port("127.0.0.1:5432:5432").localhost)
        self.assertTrue(parse_port("[::1]:5432:5432/tcp").localhost)
        self.assertTrue(parse_port("127.0.0.1:${PORT:?x}:3000").localhost)
        self.assertTrue(parse_port({"target": 80, "published": 8080, "host_ip": "127.0.0.1"}).localhost)
        self.assertTrue(parse_port({"target": 80, "published": 8080}).all_interfaces)

    def test_classify_and_secret_names(self):
        self.assertEqual(classify("db", "postgres:17"), "db")
        self.assertEqual(classify("cache", "valkey/valkey:8"), "db")
        self.assertEqual(classify("proxy", "traefik:v3"), "proxy")
        self.assertEqual(classify("mail", "axllent/mailpit:v1"), "admin")
        self.assertEqual(classify("app", "ghcr.io/me/app:1"), "app")
        self.assertTrue(is_secret_name("BETTER_AUTH_SECRET"))
        self.assertTrue(is_secret_name("DATABASE_URL"))
        self.assertFalse(is_secret_name("POSTGRES_PASSWORD_FILE"))
        self.assertFalse(is_secret_name("NEXT_PUBLIC_API_KEY"))
        self.assertFalse(is_secret_name("SESSION_TTL"))


class AuditCase(TempRepo):
    def run_script(self, script, *extra, root=None):
        res = subprocess.run([sys.executable, str(SCRIPTS / script), "--root", str(root or self.dir), "--format", "json", *extra],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertIn(res.returncode, (0, 1), res.stderr)
        return json.loads(res.stdout)

    @staticmethod
    def rules(d, part=None):
        return {f["rule"] for f in d["findings"] if part is None or part in (f.get("file") or "")}

    @staticmethod
    def msgs(d, rule):
        return [f["message"] for f in d["findings"] if f["rule"] == rule]


class DockerfileAuditTests(AuditCase):
    def test_bad_dockerfile(self):
        self.write("app/package.json", json.dumps({"dependencies": {"next": "16.0.0"}}))
        self.write("app/Dockerfile", """FROM node:latest
ARG NPM_TOKEN
ARG NEXT_PUBLIC_API_URL
ENV API_SECRET=abc
ADD src /app
COPY .env /app/.env
RUN curl -fsSL https://get.example.com | sh
RUN apt-get install -y curl
RUN npm install
COPY id_rsa /root/.ssh/id_rsa
RUN rm /root/.ssh/id_rsa
CMD node server.js
""")
        self.write("app/run.sh", "echo hi\r\n")
        d = self.run_script("audit_dockerfile.py")
        rules = self.rules(d)
        for r in ("img.01", "img.02", "img.03", "img.04", "img.05", "img.06", "img.07", "img.08", "img.09", "img.10",
                  "csec.04", "csec.05", "csec.06", "img.11", "sup.05"):
            self.assertIn(r, rules, r)
        self.assertTrue(any("NEXT_PUBLIC_API_URL" in m for m in self.msgs(d, "img.11")))
        self.assertTrue(any("deleted later" in m for m in self.msgs(d, "csec.05")))
        self.assertEqual(len(self.msgs(d, "csec.04")), 2)

    def test_template_is_clean(self):
        shutil.copy(SKILL / "assets" / "Dockerfile.nextjs-standalone", self.dir / "Dockerfile")
        shutil.copy(SKILL / "assets" / "dockerignore.node", self.dir / ".dockerignore")
        self.write("package.json", json.dumps({"dependencies": {"next": "16.0.0"}}))
        self.write("next.config.ts", "export default { output: 'standalone' }")
        self.write(".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: docker\n    directory: /\n")
        d = self.run_script("audit_dockerfile.py")
        bad = [f for f in d["findings"] if f["severity"] in ("error", "warn")]
        self.assertEqual(bad, [])
        self.assertNotIn("sup.05", self.rules(d))
        self.assertNotIn("img.11", self.rules(d))


class ComposeAuditTests(AuditCase):
    BAD = """version: "3.8"
services:
  db:
    image: postgres:latest
    ports: ["5432:5432"]
    environment:
      POSTGRES_PASSWORD: hunter2
  app:
    build: { context: ., args: { NPM_TOKEN: x } }
    privileged: true
    cap_add: [SYS_ADMIN]
    user: root
    network_mode: host
    security_opt: ["seccomp:unconfined"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc
    ports: ["3000:3000"]
    labels: ["traefik.enable=true"]
    depends_on: [db]
"""

    def test_bad_compose(self):
        self.write("compose.yaml", self.BAD)
        d = self.run_script("audit_compose.py")
        rules = self.rules(d)
        for r in ("ops.06", "img.01", "cnet.02", "cnet.03", "csec.01", "csec.03", "run.01", "run.03", "run.05", "run.08",
                  "run.09", "run.06", "run.04", "ops.01", "ops.03", "ops.04", "ops.05", "ops.07", "cnet.01", "csec.02",
                  "run.02"):
            self.assertIn(r, rules, r)
        self.assertTrue(all("hunter2" not in f["message"] for f in d["findings"]))  # values never printed

    def test_template_is_clean(self):
        shutil.copy(SKILL / "assets" / "compose.hardened.yaml", self.dir / "compose.yaml")
        (self.dir / "web").mkdir()
        self.write("web/package.json", json.dumps({"dependencies": {"next": "16.0.0"}}))
        d = self.run_script("audit_compose.py")
        bad = [f for f in d["findings"] if f["severity"] in ("error", "warn")]
        self.assertEqual(bad, [], bad)

    def test_app_port_without_proxy(self):
        # Found by the M7 eval: an app published on all interfaces with no proxy in the file was not flagged.
        self.write("compose.yaml", 'services:\n  app:\n    image: app:1.2\n    ports: ["3000:3000", "80:3000"]\n')
        d = self.run_script("audit_compose.py")
        hits = [f for f in d["findings"] if f["rule"] == "cnet.02"]
        self.assertEqual(len(hits), 1, hits)
        self.assertIn("3000:3000", hits[0]["message"])
        self.assertEqual(hits[0]["severity"], "warn")

    def test_coolify_app_port_bypasses_proxy(self):
        self.write("compose.yaml", 'services:\n  app:\n    image: app:1.2\n    environment: { SERVICE_FQDN_APP: x }\n    ports: ["3000:3000"]\n')
        d = self.run_script("audit_compose.py")
        self.assertIn("cool.01", self.rules(d))
        self.assertNotIn("cnet.03", self.rules(d))

    def test_docker_api_port_and_disabled_db_auth(self):
        self.write("compose.yaml", """services:
  dind:
    image: docker:27-dind
    ports: ["2375:2375", "127.0.0.1:2376:2376"]
  pg:
    image: postgres:17
    environment: { POSTGRES_HOST_AUTH_METHOD: trust }
  my:
    image: mysql:8.4
    environment: { MYSQL_ALLOW_EMPTY_PASSWORD: "yes", MYSQL_ROOT_PASSWORD: "${DB_PW:?}" }
  ok:
    image: mariadb:11
    environment: { MARIADB_ALLOW_EMPTY_ROOT_PASSWORD: "no", POSTGRES_HOST_AUTH_METHOD: scram-sha-256 }
""")
        self.write("compose.dev.yaml", "services:\n  pg:\n    image: postgres:17\n    environment: { POSTGRES_HOST_AUTH_METHOD: trust }\n")
        d = self.run_script("audit_compose.py")
        api = [f for f in d["findings"] if "Docker Engine API" in f["message"]]
        self.assertEqual([(f["rule"], f["severity"]) for f in api], [("cnet.02", "error")])  # 127.0.0.1 binding is fine
        auth = [(f["file"], f["severity"], f["message"].split("`")[1]) for f in d["findings"] if f["rule"] == "csec.07"]
        self.assertEqual(sorted(auth), [("compose.dev.yaml", "info", "pg"), ("compose.yaml", "error", "my"),
                                        ("compose.yaml", "error", "pg")])

    def test_dev_file_relaxed_and_platform_allowlist(self):
        self.write("compose.dev.yaml", """services:
  db:
    image: postgres:17-alpine
    environment: { POSTGRES_PASSWORD: dev }
    ports: ["127.0.0.1:5432:5432"]
""")
        self.write("compose.platform.yaml", """services:
  coolify-proxy:
    image: traefik:v3.1
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]
""")
        d = self.run_script("audit_compose.py")
        dev = [f for f in d["findings"] if "compose.dev" in f["file"]]
        self.assertEqual([(f["rule"], f["severity"]) for f in dev], [("csec.01", "info")])
        self.assertIn("cool.03", self.rules(d, "platform"))
        self.assertNotIn("run.01", self.rules(d, "platform"))

    def test_read_only_next_without_cache_tmpfs(self):
        self.write("web/package.json", json.dumps({"dependencies": {"next": "16.0.0"}}))
        self.write("compose.yaml", """services:
  app:
    build: ./web
    read_only: true
    tmpfs: ["/tmp"]
""")
        d = self.run_script("audit_compose.py")
        self.assertTrue(any(".next/cache" in m for m in self.msgs(d, "run.07")))


class RuntimeAndHostTests(unittest.TestCase):
    def test_runtime_audit_function(self):
        import audit_runtime
        rb, report = RuleBook(SKILL), Report(tool="t", root="x")
        containers = [
            {"Name": "/db", "Config": {"Image": "postgres:17", "User": "", "Healthcheck": {"Test": ["CMD", "pg_isready"]}},
             "HostConfig": {"PortBindings": {"5432/tcp": [{"HostIp": "", "HostPort": "5432"}]}, "Memory": 0,
                            "RestartPolicy": {"Name": "unless-stopped"}, "LogConfig": {"Type": "json-file", "Config": {}}},
             "State": {"Status": "running", "Health": {"Status": "healthy"}}, "Mounts": []},
            {"Name": "/app", "Config": {"Image": "app:1", "User": ""},
             "HostConfig": {"Privileged": True, "Memory": 0, "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "local"}},
             "State": {"Status": "running"}, "Mounts": [{"Source": "/var/run/docker.sock", "Type": "bind", "RW": True}]},
            {"Name": "/coolify-proxy", "Config": {"Image": "traefik:v3"}, "HostConfig": {"PortBindings": {}},
             "State": {"Status": "running"}, "Mounts": [{"Source": "/var/run/docker.sock", "Type": "bind", "RW": False}]},
        ]
        audit_runtime.audit(containers, rb, report, {"coolify-proxy"})
        got = {(f.rule, f.file) for f in report.findings}
        self.assertIn(("cnet.02", "container:db"), got)
        self.assertIn(("ops.05", "container:db"), got)
        self.assertIn(("run.01", "container:app"), got)
        self.assertIn(("run.03", "container:app"), got)
        self.assertIn(("img.02", "container:app"), got)
        self.assertIn(("cool.03", "container:coolify-proxy"), got)
        self.assertNotIn(("run.01", "container:coolify-proxy"), got)

    def test_host_audit_function(self):
        import audit_host
        rb, report = RuleBook(SKILL), Report(tool="t", root="x")
        audit_host.audit({"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"], "log-level": "debug"},
                         {"ServerVersion": "29.0.1", "KernelVersion": "6.8", "SecurityOptions": ["name=apparmor"], "LoggingDriver": "json-file"},
                         "/usr/bin/dockerd", [("db", "0.0.0.0:5432->5432/tcp"), ("proxy", "0.0.0.0:443->443/tcp")], None, rb, report)
        rules = {f.rule for f in report.findings}
        for r in ("host.01", "host.02", "host.03", "host.04", "host.05", "host.06"):
            self.assertIn(r, rules, r)
        self.assertEqual(len([f for f in report.findings if f.rule == "host.06"]), 1)  # 443 on the proxy is fine


class ContentTests(unittest.TestCase):
    def test_rule_index_in_sync(self):
        res = subprocess.run([sys.executable, str(SCRIPTS / "build_rule_index.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_skill_md(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        fm = re.match(r"^---\n(.*?)\n---\n", text, re.S).group(1)
        self.assertIn("name: container-standards", fm)
        desc = re.search(r"^description: (.+)$", fm, re.M).group(1)
        self.assertLessEqual(len(desc), 1024)
        for asset in re.findall(r"`((?:Dockerfile|dockerignore|compose|daemon|ci-)[\w.-]*)`", text.split("Start from `assets/`:", 1)[1].split("\n")[0]):
            self.assertTrue((SKILL / "assets" / asset).exists(), asset)
        for ref in re.findall(r"(?<![\w/-])(\d{2}-[\w-]+\.md)", text):
            self.assertTrue((SKILL / "references" / ref).exists(), ref)

    def test_banners(self):
        for p in sorted((SKILL / "references").glob("1*.md")):
            t = p.read_text(encoding="utf-8")
            self.assertIn("**Rule IDs:**", t[:800], p.name)


if __name__ == "__main__":
    unittest.main()
