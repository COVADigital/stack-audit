import json
import unittest

from helpers import TempRepo
from wclib.stack import detect_stack, major_of


class MajorTests(unittest.TestCase):
    def test_major_of(self):
        self.assertEqual(major_of("16.1.0"), 16)
        self.assertEqual(major_of("v4.2"), 4)
        self.assertIsNone(major_of(None))
        self.assertIsNone(major_of("latest"))


class StackTests(TempRepo):
    def _pkg(self, deps=None, dev=None, scripts=None, **extra):
        data = {"name": "app", "dependencies": deps or {}, "devDependencies": dev or {}, "scripts": scripts or {}}
        data.update(extra)
        self.write("package.json", json.dumps(data))

    def test_next16_app_router_from_package_lock(self):
        self._pkg(
            deps={"next": "^16.0.0", "react": "^19.2.0", "zod": "^4.1.0", "drizzle-orm": "^0.44.0",
                  "better-auth": "^1.3.0", "next-intl": "^4.0.0"},
            dev={"tailwindcss": "^4.1.0", "typescript": "^5.9.0"},
            scripts={"lint": "next lint"},
        )
        self.write("package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/next": {"version": "16.4.5"}, "node_modules/react": {"version": "19.2.7"}},
        }))
        self.write("src/app/page.tsx", "export default function P(){return null}")
        self.write("middleware.ts", "export function middleware(){}")
        self.write("next.config.ts", """
            // cacheComponents: false  (comment must be ignored)
            const config = {
              cacheComponents: true,
              reactCompiler: true,
              output: 'standalone',
              async headers() { return [] },
            };
            export default config;
        """)
        p = detect_stack(self.dir)
        self.assertEqual(p.package_manager, "npm")
        self.assertEqual(p.packages["next"]["installed"], "16.4.5")
        self.assertEqual(p.next_major, 16)
        self.assertEqual(p.major("zod"), 4)
        self.assertEqual(p.packages["tailwindcss"]["major"], 4)
        self.assertTrue(p.packages["tailwindcss"]["dev"])
        self.assertEqual(p.categories["orm"], "drizzle-orm")
        self.assertEqual(p.categories["auth"], "better-auth")
        self.assertEqual(p.categories["i18n"], "next-intl")
        self.assertEqual(p.router, {"app": "src/app", "pages": None})
        self.assertTrue(p.cache_components)
        self.assertTrue(p.next_config["reactCompiler"])
        self.assertEqual(p.next_config["output"], "standalone")
        self.assertTrue(p.next_config["headers"])
        self.assertEqual(p.request_interceptor, "middleware.ts")
        self.assertTrue(any("proxy.ts" in n for n in p.notes))
        self.assertTrue(any("next lint" in n for n in p.notes))
        json.loads(p.to_json())  # serialisable

    def test_commented_flag_not_detected(self):
        self._pkg(deps={"next": "15.5.0"})
        self.write("next.config.mjs", "export default { /* cacheComponents: true */ }")
        p = detect_stack(self.dir)
        self.assertFalse(p.cache_components)
        self.assertEqual(p.next_major, 15)  # from declared range

    def test_pnpm_lock_and_node_modules_precedence(self):
        self._pkg(deps={"next": "^16", "react": "^19"})
        self.write("pnpm-lock.yaml", "importers:\n  .:\n    dependencies:\n      next:\n        specifier: ^16\n        version: 16.2.1(react@19.2.0)\n      react:\n        specifier: ^19\n        version: 19.2.0\n")
        self.write("node_modules/react/package.json", json.dumps({"version": "19.3.1"}))
        p = detect_stack(self.dir)
        self.assertEqual(p.package_manager, "pnpm")
        self.assertEqual(p.packages["next"]["installed"], "16.2.1")
        self.assertEqual(p.packages["react"]["installed"], "19.3.1")  # node_modules wins

    def test_docker_ci_and_monorepo(self):
        self._pkg(workspaces=["apps/*", "packages/*"])
        self.write("Dockerfile", "FROM node:22")
        self.write("compose.yaml", "services: {}")
        self.write(".dockerignore", ".env")
        self.write(".github/workflows/ci.yml", "on: push")
        self.write(".github/dependabot.yml", "version: 2")
        p = detect_stack(self.dir)
        self.assertEqual(p.docker["dockerfiles"], ["Dockerfile"])
        self.assertEqual(p.docker["compose"], ["compose.yaml"])
        self.assertTrue(p.docker["dockerignore"])
        self.assertEqual(p.ci["github_actions"], ["ci.yml"])
        self.assertTrue(p.ci["dependabot"])
        self.assertEqual(p.workspaces, ["apps/*", "packages/*"])
        self.assertTrue(any("Monorepo" in n for n in p.notes))

    def test_no_package_json(self):
        p = detect_stack(self.dir)
        self.assertFalse(p.has_package_json)
        self.assertIsNone(p.next_major)


if __name__ == "__main__":
    unittest.main()
