"""A test built on grant_harness that raises after the app booted fails and exits; it does not hang (1.24.2).

Run: venv/bin/python tests/test_harness_failure_exit.py   (about 20 seconds)
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from grant_harness import check, failures  # noqa: E402

BODY = """
import sys
sys.path.insert(0, %r)
import grant_harness as h

async def main():
    env = await h.boot(names=("owner",), superadmin=("owner",))
    raise RuntimeError("a check blew up after the app booted")

h.run(main, 30)
print("NOT REACHED")
"""

try:
    cp = subprocess.run([sys.executable, "-c", BODY % str(HERE)], capture_output=True, text=True, timeout=60)
    hung = False
except subprocess.TimeoutExpired:
    hung = True
    cp = None
check("a test that raises after boot does not hang", not hung)
if cp is not None:
    check("... it exits with a failure code", cp.returncode == 1, str(cp.returncode))
    check("... and says why", "a check blew up" in cp.stdout + cp.stderr and "NOT REACHED" not in cp.stdout)
if failures:
    print("\ntest_harness_failure_exit: FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_harness_failure_exit: all checks passed")
