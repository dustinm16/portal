#!/usr/bin/env python3
"""Unit tests for stage_smoke.py that need no staged server.

Covers the runner's handling of check modules (a module that records nothing
must fail) and the staged .env (request limits raised, even over a copied .env).

Usage: python tools/test_stage_smoke_checks.py
"""
import asyncio
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


if __name__ == "__main__":
    unittest.main()
