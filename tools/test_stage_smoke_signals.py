#!/usr/bin/env python3
"""Check that stage_smoke.py cleans up when it is killed by a signal.

For each of SIGINT, SIGTERM and SIGHUP: start the runner on a test port, wait
until the staged server answers, send the signal to the runner, then require
that the runner exits, the port is free and the stage directory is gone.

Usage: python tools/test_stage_smoke_signals.py [--port 8461]
Exit status 0 when every signal is cleaned up, 1 otherwise.
"""
import argparse
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

RUNNER = Path(__file__).resolve().parent / "stage_smoke.py"


def listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def one(sig: int, port: int) -> bool:
    name = signal.Signals(sig).name
    if listening(port):
        print(f"FAIL  {name}: port {port} already in use")
        return False
    proc = subprocess.Popen([sys.executable, str(RUNNER), "--port", str(port), "--selftest-hang"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    stage = None
    try:
        deadline = time.time() + 120
        while time.time() < deadline and not listening(port):
            if proc.poll() is not None:
                break
            time.sleep(0.3)
        if not listening(port):
            print(f"FAIL  {name}: staged server never came up")
            return False
        proc.send_signal(sig)
        try:
            out, _ = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            print(f"FAIL  {name}: runner did not exit after the signal")
            return False
        m = re.search(r"stage dir: (\S+)", out)
        stage = Path(m.group(1)) if m else None
    finally:
        if proc.poll() is None:
            proc.kill()
    problems = []
    if listening(port):
        problems.append(f"port {port} still listening")
    if stage is None:
        problems.append("stage dir not reported")
    elif stage.exists():
        problems.append(f"stage dir {stage} left behind")
    if problems:
        print(f"FAIL  {name}: " + "; ".join(problems))
        return False
    print(f"ok    {name}: runner exited {proc.returncode}, server stopped, stage dir removed")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8461)
    args = ap.parse_args()
    results = [one(s, args.port) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
