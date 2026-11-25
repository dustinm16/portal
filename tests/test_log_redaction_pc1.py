"""The proxied-page credential is redacted from log lines in both spellings of the tilde: ~pc1.<token> and %7Epc1.<token>.

Run: venv/bin/python tests/test_log_redaction_pc1.py   (plain script, exit code 0 means pass)
"""

import io
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import logger as portal_logger  # noqa: E402

TOKEN = "AbCdEf012345.GhIjKl-6789_xyz.MAC0123456789abcdef"


def render(msg):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    handler.addFilter(portal_logger.SensitiveDataFilter())
    log = logging.getLogger("test_log_redaction_pc1." + str(id(handler)))
    log.propagate = False
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)
    log.info(msg)
    return stream.getvalue()


def access(path):
    return f'127.0.0.1 [25/Nov/2026:10:00:00 +0000] "GET {path} HTTP/1.1" 200 512 "-" "UA"'


def test_literal_tilde():
    out = render(access(f"/proxy/abc123/~pc1.{TOKEN}/app/index.html"))
    assert "/proxy/abc123/~[REDACTED]/app/index.html" in out, out
    assert TOKEN.split(".")[0] not in out, out


def test_percent_encoded_tilde():
    for spelling in ("%7E", "%7e"):
        out = render(access(f"/proxy/abc123/{spelling}pc1.{TOKEN}/app/index.html"))
        assert TOKEN.split(".")[0] not in out and TOKEN.split(".")[1] not in out, out
        assert "/proxy/abc123/~[REDACTED]/app/index.html" in out, out


def test_other_paths_unchanged():
    line = access("/proxy/abc123/app/%7Epage")
    assert render(line).endswith(line + "\n"), render(line)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
    sys.exit(1 if failed else 0)
