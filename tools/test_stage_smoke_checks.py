#!/usr/bin/env python3
"""Unit tests for stage_smoke.py that need no staged server.

Covers the runner's handling of check modules (a module that records nothing
must fail) and the staged .env (request limits raised, even over a copied .env).

Usage: python tools/test_stage_smoke_checks.py
"""
import asyncio
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_smoke  # noqa: E402


def _ctx(tmp: Path) -> "stage_smoke.Ctx":
    return stage_smoke.Ctx(tmp, 8461, {}, "admin", None)


def _module(tmp: Path, name: str, body: str) -> Path:
    path = tmp / f"check_{name}.py"
    path.write_text(f"async def run(ctx):\n{body}\n")
    return path


class RunChecksTest(unittest.TestCase):
    def run_modules(self, **bodies):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            ctx = _ctx(tmp)
            mods = [_module(tmp, n, b) for n, b in bodies.items()]
            asyncio.run(stage_smoke.run_checks(ctx, mods, False))
            return ctx

    def test_module_without_results_fails(self):
        ctx = self.run_modules(silent="    return")
        self.assertEqual([(r[0], r[1]) for r in ctx.results], [("FAIL", "silent")])

    def test_early_return_before_checks_fails(self):
        ctx = self.run_modules(early="    if True:\n        return\n    ctx.ok('never reached', True)")
        self.assertEqual(len(ctx.failed), 1)

    def test_ok_and_skip_count_as_results(self):
        ctx = self.run_modules(good="    ctx.ok('a', True)", skipped="    ctx.skip('b', 'why')")
        self.assertEqual([r[0] for r in ctx.results], ["PASS", "SKIP"])
        self.assertFalse(ctx.failed)

    def test_results_of_other_modules_do_not_hide_a_silent_one(self):
        ctx = self.run_modules(a_good="    ctx.ok('a', True)", b_silent="    pass")
        self.assertEqual([(r[0], r[1]) for r in ctx.results], [("PASS", "a_good"), ("FAIL", "b_silent")])


class WriteEnvTest(unittest.TestCase):
    def values(self, base_env=None):
        with tempfile.TemporaryDirectory() as d:
            stage = Path(d)
            stage_smoke.write_env(stage, 8461, stage / "c.pem", stage / "k.pem", base_env)
            return dict(line.split("=", 1) for line in (stage / ".env").read_text().splitlines())

    def test_fresh_env_raises_request_limit(self):
        env = self.values()
        self.assertGreaterEqual(int(env["RATE_LIMIT_REQUESTS"]), 10000)
        self.assertGreater(int(env["RATE_LIMIT_WINDOW"]), 0)

    def test_copied_env_cannot_lower_the_limit(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "base.env"
            base.write_text("RATE_LIMIT_REQUESTS=5\nRATE_LIMIT_WINDOW=3600\nJWT_SECRET=x\n")
            env = self.values(base)
        self.assertGreaterEqual(int(env["RATE_LIMIT_REQUESTS"]), 10000)
        self.assertEqual(env["RATE_LIMIT_WINDOW"], "60")
        self.assertEqual(env["JWT_SECRET"], "x")


class _StubCtx:
    """What a check module touches, with nothing behind it: no server, no database."""

    def __init__(self, admin_password):
        self.admin_user = "admin"
        self.admin_password = admin_password
        self.results = []
        self.touched = []

    def ok(self, name, passed, detail=""):
        self.results.append(("PASS" if passed else "FAIL", name))

    def skip(self, name, reason=""):
        self.results.append(("SKIP", name))

    async def run_py(self, *a, **k):
        self.touched.append("run_py")
        return 1, "no server in this test"

    def http(self, *a, **k):
        self.touched.append("http")
        raise AssertionError("no request may be made")


def _load_check(name: str):
    path = Path(__file__).resolve().parent / "smoke_checks" / f"check_{name}.py"
    spec = importlib.util.spec_from_file_location(f"check_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TokensCheckWithoutPasswordTest(unittest.TestCase):
    """A --from-db run has no admin password: the tokens check says so once and fails nothing."""

    def test_no_admin_password_is_one_skip_and_no_failure(self):
        ctx = _StubCtx(None)
        asyncio.run(asyncio.wait_for(_load_check("tokens").run(ctx), 20))
        self.assertEqual([r[0] for r in ctx.results], ["SKIP"], ctx.results)
        self.assertEqual(ctx.touched, [], "the check must not create users or sign in")

    def test_empty_admin_password_is_the_same(self):
        ctx = _StubCtx("")
        asyncio.run(asyncio.wait_for(_load_check("tokens").run(ctx), 20))
        self.assertEqual([r[0] for r in ctx.results], ["SKIP"], ctx.results)


REPO = Path(__file__).resolve().parent.parent


class CleanupLeavesNoUsersTest(unittest.TestCase):
    """The smoke checks that make their own users delete them again (run against a temporary database)."""

    def py(self, db_path, code):
        env = dict(os.environ, DATABASE_PATH=str(db_path), JWT_SECRET="x" * 64)
        proc = subprocess.run([sys.executable, "-c", code], cwd=str(REPO), env=env, timeout=120,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout[-500:])
        return proc.stdout

    def smoke_users(self, db_path):
        con = sqlite3.connect(str(db_path))
        try:
            return [r[0] for r in con.execute("SELECT username FROM users WHERE username LIKE 'smoke\\_%' ESCAPE '\\' "
                                              "OR username LIKE 'hlt%'")]
        finally:
            con.close()

    def test_maintenance(self):
        mod = _load_check("maintenance")
        with tempfile.TemporaryDirectory() as d:
            db_path = Path(d) / "t.db"
            self.py(db_path, mod.SETUP)
            self.assertEqual(len(self.smoke_users(db_path)), 3)
            self.py(db_path, mod.CLEANUP)
            self.assertEqual(self.smoke_users(db_path), [])

    def test_blockref(self):
        mod = _load_check("blockref")
        with tempfile.TemporaryDirectory() as d:
            db_path = Path(d) / "t.db"
            self.py(db_path, mod.CREATE_MEMBER)
            self.assertEqual(len(self.smoke_users(db_path)), 1)
            self.py(db_path, mod.DELETE_MEMBER)
            self.assertEqual(self.smoke_users(db_path), [])

    def test_health(self):
        mod = _load_check("health")
        with tempfile.TemporaryDirectory() as d:
            db_path = Path(d) / "t.db"
            params = json.dumps({"pw": "Health-smoke-pw-1", "pre": "hlt1a2b3c", "port": 40000})
            self.py(db_path, mod.SETUP % {"params": params})
            self.assertEqual(len(self.smoke_users(db_path)), 3)
            self.py(db_path, mod.CLEANUP % {"like": "hlt1a2b3c%"})
            self.assertEqual(self.smoke_users(db_path), [])
            con = sqlite3.connect(str(db_path))
            try:
                left = con.execute("SELECT COUNT(*) FROM user_connections WHERE name LIKE 'hlt1a2b3c%'").fetchone()[0]
            finally:
                con.close()
            self.assertEqual(left, 0)


if __name__ == "__main__":
    unittest.main()
