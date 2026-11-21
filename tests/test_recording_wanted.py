"""recording_wanted: exactly True, 1, "1" and "true" (any case) switch recording on.

Run: venv/bin/python tests/test_recording_wanted.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

from config import Config  # noqa: E402
import session_recording as sr  # noqa: E402

failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        failures.append(name)


Config.RECORDING_ENABLED = True
for value in (True, 1, "1", "true", "True", "TRUE", "tRuE"):
    check(f"{value!r} switches recording on", sr.recording_wanted({"recording": value}) is True)
for value in (False, 0, "0", "false", "", " true", "true ", "yes", 2, 1.0, True and None, None, [], {}, ["true"]):
    check(f"{value!r} leaves recording off", sr.recording_wanted({"recording": value}) is False)
check("a missing key is off", sr.recording_wanted({}) is False)
check("a config that is not a dict is off", sr.recording_wanted("recording") is False
      and sr.recording_wanted(None) is False)
Config.RECORDING_ENABLED = False
check("the portal-wide switch off wins", sr.recording_wanted({"recording": True}) is False)

print(f"\n{len(failures)} failed" if failures else "\nall passed")
sys.exit(1 if failures else 0)
