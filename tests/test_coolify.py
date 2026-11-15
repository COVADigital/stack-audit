"""Tests for the Coolify live checks (audit_coolify.py) and the add-on helper (coolify_addon.py)."""

import copy
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from helpers import PLUGIN_ROOT, TempRepo
from wclib.rules import RuleBook

SKILL = PLUGIN_ROOT / "skills" / "container-standards"
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

import audit_coolify  # noqa: E402
import coolify_addon  # noqa: E402

CLEAN = {
    "snapshot_version": 1, "collected_at": "2026-11-15T20:00:00Z", "coolify_version": "4.7.5",
    "projects": ["Shop"], "read_sensitive": True,
    "servers": [{"name": "main", "user": "deploy", "settings": {
        "is_image_scan_enabled": True, "is_auto_security_updates_enabled": True, "is_ssh_host_key_check_disabled": False,
        "is_terminal_enabled": False, "delete_unused_volumes": False, "cloudflare_tunnel_integration_token_id": 3,
        "patch_check_result": {"security_updates": 0, "reboot_required": False, "updates": [],
                               "kernels": {"running": "6.8.0-149", "boot": "6.8.0-149"}}}}],
    "applications": [{"name": "web", "project": "Shop", "build_pack": "dockerfile", "ports_mappings": None,
                      "health_check_enabled": True, "limits_memory": "512m", "limits_cpus": "1",
                      "custom_docker_run_options": "--init",
                      "env_keys": [{"key": "DATABASE_URL", "is_buildtime": False}, {"key": "NEXT_PUBLIC_SITE", "is_buildtime": True}],
                      "storages": [{"name": "web-data", "mount_path": "/data", "owner": "application:1"}],
                      "security": {"status": "ok"}}],
    "services": [{"name": "n8n", "project": "Shop", "redact_all_env_values_in_logs": True,
                  "applications": [{"name": "n8n", "image": "n8nio/n8n:1.80.0", "ports": ""}],
                  "databases": [{"name": "postgresql", "image": "postgres:17-alpine", "is_public": False}],
                  "env_keys": [], "storages": [], "security": {"status": "ok"}}],
    "databases": [{"name": "shop-db", "project": "Shop", "is_public": False, "image": "postgres:17",
                   "backups": [{"enabled": True, "save_s3": True, "executions": [{"status": "success", "created_at": "2026-11-15"}]}],
                   "env_keys": [], "storages": [], "security": {"status": "ok"}}],
}


def bad_snapshot() -> dict:
    s = copy.deepcopy(CLEAN)
    srv = s["servers"][0]
    srv["user"] = "root"
    srv["settings"].update({"is_image_scan_enabled": False, "is_auto_security_updates_enabled": False,
                            "is_ssh_host_key_check_disabled": True, "is_terminal_enabled": True, "delete_unused_volumes": True,
                            "patch_check_result": {"security_updates": 2, "reboot_required": True,
                                                   "updates": [{"package": "docker-ce", "risk": "docker"}],
                                                   "kernels": {"running": "6.8.0-147", "boot": "6.8.0-149"}}})
    app = s["applications"][0]
    app.update({"ports_mappings": "3000:3000", "health_check_enabled": False, "limits_memory": "0", "limits_cpus": "0",
                "custom_docker_run_options": "--privileged -v /var/run/docker.sock:/var/run/docker.sock --network=host",
                "security": {"status": "update_now", "critical_count": 2, "high_count": 1, "any_exploited": True}})
    app["env_keys"].append({"key": "STRIPE_SECRET_KEY", "is_buildtime": True})
    app["storages"].append({"name": "web-data-old", "mount_path": "/data", "owner": "application:1"})
    svc = s["services"][0]
    svc["redact_all_env_values_in_logs"] = False
    svc["applications"][0].update({"image": "n8nio/n8n", "ports": "5678:5678"})
    svc["databases"][0].update({"is_public": True, "public_port": 5433})
    svc["security"] = {"status": "update_available"}
    db = s["databases"][0]
    db["backups"] = [{"enabled": True, "save_s3": False, "executions": [{"status": "failed", "created_at": "2026-11-14"}]}]
    s["databases"].append({"name": "orphan-db", "project": "Shop", "image": "redis:latest", "backups": []})
    return s


def run(snap, projects=None):
    return audit_coolify.CoolifyAudit(snap, RuleBook(SKILL), projects).run()


class CoolifyAuditTests(unittest.TestCase):
    def test_clean_snapshot_has_no_findings(self):
        report = run(CLEAN)
        self.assertEqual([(f.rule, f.message) for f in report.findings], [])
        self.assertTrue(any("service stacks" in n for n in report.not_checked))
        self.assertEqual(report.meta["resources"], {"applications": 1, "services": 1, "databases": 1})

    def test_bad_snapshot_fires_every_live_rule(self):
        report = run(bad_snapshot())
        got = {f.rule for f in report.findings}
        for rule in ("cool.01", "cool.02", "cool.06", "cool.07", "cool.08", "cool.09", "cool.10", "cool.11",
                     "host.01", "sup.01", "ops.02", "ops.03", "run.06", "img.01", "run.01", "run.03", "run.05"):
            self.assertIn(rule, got, rule)
        sev = {(f.rule, f.severity) for f in report.findings}
        self.assertIn(("sup.01", "error"), sev)   # exploited image
        self.assertIn(("ops.02", "error"), sev)   # last backup failed
        self.assertIn(("cool.02", "error"), sev)
        leak = next(f for f in report.findings if f.rule == "cool.06")
        self.assertIn("STRIPE_SECRET_KEY", leak.message)
        self.assertNotIn("NEXT_PUBLIC_SITE", leak.message)
        self.assertEqual(next(f for f in report.findings if f.rule == "cool.11").confidence, "medium")
        text = report.render("md")
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", text)  # docker run options are never quoted

    def test_runtime_only_secret_and_image_pack_not_flagged(self):
        s = copy.deepcopy(CLEAN)
        s["applications"][0].update({"build_pack": "dockerimage", "docker_registry_image_name": "ghcr.io/acme/web",
                                     "docker_registry_image_tag": "1.4.2"})
        s["applications"][0]["env_keys"].append({"key": "API_SECRET", "is_buildtime": True})
        self.assertEqual([f.rule for f in run(s).findings], [])  # nothing is built, so build-time vars can't leak
        s["applications"][0]["docker_registry_image_tag"] = None
        self.assertEqual([f.rule for f in run(s).findings], ["img.01"])

    def test_project_filter(self):
        s = bad_snapshot()
        s["services"][0]["project"] = "Other"
        rules = {f.rule for f in run(s, ["shop"]).findings}
        self.assertNotIn("cool.10", rules)
        self.assertIn("cool.06", rules)

    def test_unsafe_snapshots_rejected(self):
        for mutate in (lambda s: s["applications"][0]["env_keys"][0].__setitem__("value", "hunter2"),
                       lambda s: s["databases"][0].__setitem__("internal_db_url", "postgres://u:p@db:5432/x"),
                       lambda s: s["applications"][0].__setitem__("start_command", "node server.js"),
                       lambda s: s["servers"][0].__setitem__("note", "https://admin:pw@example.com")):
            s = copy.deepcopy(CLEAN)
            mutate(s)
            with self.assertRaises(audit_coolify.SnapshotError) as ctx:
                audit_coolify.check_safe(s)
            self.assertNotIn("hunter2", str(ctx.exception))
        audit_coolify.check_safe(CLEAN)  # ids such as *_token_id are fine

    def test_cli(self):
        t = TempRepo("setUp")
        t.setUp()
        try:
            good = t.write("snap.json", json.dumps(bad_snapshot()))
            res = subprocess.run([sys.executable, str(SCRIPTS / "audit_coolify.py"), "--snapshot", str(good), "--format", "json",
                                  "--strict"], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(res.returncode, 1, res.stderr)
            self.assertIn("cool.02", {f["rule"] for f in json.loads(res.stdout)["findings"]})
            old = t.write("old.json", json.dumps({"snapshot_version": 0}))
            res = subprocess.run([sys.executable, str(SCRIPTS / "audit_coolify.py"), "--snapshot", str(old)],
                                 capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(res.returncode, 2)
            self.assertIn("version 1", res.stderr)
        finally:
            t.tearDown()


class CoolifyAddonTests(TempRepo):
    def test_choice_round_trip(self):
        with mock.patch.dict(os.environ, {"HOME": str(self.dir), "USERPROFILE": str(self.dir)}):
            self.assertEqual(coolify_addon.read_state(), {})
            coolify_addon.set_choice("no")
            self.assertEqual(coolify_addon.read_state(), {"coolify": "no"})
            self.assertTrue(str(coolify_addon.state_file()).startswith(str(self.dir)))

    def test_mcp_url(self):
        self.assertEqual(coolify_addon.mcp_url("https://coolify.example.com"), "https://coolify.example.com/mcp")
        self.assertEqual(coolify_addon.mcp_url("https://coolify.example.com/mcp/"), "https://coolify.example.com/mcp")
        self.assertEqual(coolify_addon.mcp_url("http://localhost:8000"), "http://localhost:8000/mcp")
        for bad in ("http://coolify.example.com", "https://u:p@coolify.example.com", "https://x.example.com/?t=1", "coolify"):
            with self.assertRaises(ValueError, msg=bad):
                coolify_addon.mcp_url(bad)

    def test_install_commands_never_hold_the_token(self):
        with mock.patch.dict(os.environ, {"COOLIFY_TOKEN": "1|real-token"}):
            cmds = coolify_addon.install_commands("https://coolify.example.com", "both")
        claude, codex = cmds["claude"], cmds["codex"]
        self.assertEqual(claude[:4], ["claude", "mcp", "add-json", "coolify"])
        self.assertEqual(claude[-2:], ["--scope", "user"])
        self.assertEqual(json.loads(claude[4])["headers"]["Authorization"], "Bearer ${COOLIFY_TOKEN}")
        self.assertEqual(codex, ["codex", "mcp", "add", "coolify", "--url", "https://coolify.example.com/mcp",
                                 "--bearer-token-env-var", "COOLIFY_TOKEN"])
        self.assertNotIn("real-token", json.dumps(cmds))
        self.assertEqual(list(coolify_addon.install_commands("https://c.example.com", "codex")), ["codex"])

    def test_dry_run_cli(self):
        res = subprocess.run([sys.executable, str(SCRIPTS / "coolify_addon.py"), "install", "--url", "https://c.example.com",
                              "--client", "both", "--dry-run"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("${COOLIFY_TOKEN}", res.stdout)
        self.assertIn("--bearer-token-env-var COOLIFY_TOKEN", res.stdout)

    def test_token_input_validated(self):
        for bad in ("", "has space", "x" * 2000):
            with mock.patch.object(coolify_addon.sys, "stdin", mock.Mock(isatty=lambda: False, readline=lambda: bad + "\n")):
                with self.assertRaises(ValueError):
                    coolify_addon.read_token()
        with mock.patch.object(coolify_addon.sys, "stdin", mock.Mock(isatty=lambda: False, readline=lambda: "1|abc\n")):
            self.assertEqual(coolify_addon.read_token(), "1|abc")

    def test_store_token_posix_file_and_profile(self):
        with mock.patch.dict(os.environ, {"HOME": str(self.dir), "USERPROFILE": str(self.dir), "SHELL": "/bin/zsh"}):
            where = coolify_addon.store_token("1|tok'en", windows=False)
            coolify_addon.store_token("1|tok'en", windows=False)  # second run must not duplicate the profile line
        env_file = self.dir / ".config" / "stack-audit" / "coolify.env"
        self.assertNotIn("tok", where)
        self.assertEqual(env_file.read_text(encoding="utf-8"), "export COOLIFY_TOKEN='1|tok'\"'\"'en'\n")
        self.assertEqual((self.dir / ".zshrc").read_text(encoding="utf-8").count("coolify.env"), 2)  # one line, two mentions
        if os.name != "nt":
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

    def test_status_reports_clients_without_running_them(self):
        with mock.patch.object(coolify_addon.shutil, "which", lambda name: None):
            self.assertEqual(coolify_addon.client_status(), {"claude": {"cli": False, "server": False},
                                                             "codex": {"cli": False, "server": False}})
            self.assertIn("not found", coolify_addon.verify())


class CoolifyContentTests(unittest.TestCase):
    def test_reference_lists_live_rules_and_recipe(self):
        text = (SKILL / "references" / "17-coolify.md").read_text(encoding="utf-8")
        for nn in range(1, 12):
            self.assertIn(f"## {nn:02d}. ", text)
        self.assertIn("## Live checks", text)
        self.assertIn("get_env_values", text)  # the recipe names what must never be called
        self.assertIn('"snapshot_version": 1', text)


if __name__ == "__main__":
    unittest.main()
