"""Every test file that boots the portal installs the outbound guard before it imports the portal (1.24.2).

The eight files added in 1.24.1 did not all install tests/outbound_guard.py themselves: a mistake in one of them could
have reached a real host. Each must either call outbound_guard.install() at the top level before any import of server
or of another test module, or import tests/grant_harness.py (which installs it as it is imported).
Run: venv/bin/python tests/test_outbound_guard_everywhere.py
"""

import ast
import sys
from pathlib import Path

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def finish(label):
    if failures:
        print(f"\n{label}: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print(f"\n{label}: all checks passed")


HERE = Path(__file__).resolve().parent
FILES = ("test_access_confirm", "test_access_whep_kick", "test_anonymous_moderation", "test_anonymous_reactions",
         "test_anonymous_unban_http", "test_connection_repoint", "test_proxy_origin", "test_stream_notifications_withdrawn")


def first_guard_position(tree):
    """Index of the first top-level statement that installs the guard, or None."""
    for i, node in enumerate(tree.body):
        if isinstance(node, ast.Import) and any(a.name == "grant_harness" for a in node.names):
            return i
        if isinstance(node, ast.ImportFrom) and node.module == "grant_harness":
            return i
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "install" and getattr(node.value.func.value, "id", "") == "outbound_guard"):
            return i
    return None


def first_portal_import(tree):
    """Index of the first top-level import of server or of a sibling test module (they may load the portal)."""
    for i, node in enumerate(tree.body):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for n in names:
            root = n.split(".")[0]
            if root in ("server", "database", "auth", "config") or root.startswith("test_"):
                return i
    return None


for name in FILES:
    tree = ast.parse((HERE / (name + ".py")).read_text())
    guard, portal = first_guard_position(tree), first_portal_import(tree)
    check(f"{name}: installs the outbound guard before it imports the portal",
          guard is not None and (portal is None or guard < portal), f"guard at {guard}, portal import at {portal}")
finish("test_outbound_guard_everywhere")
