"""Log redaction checks: feed sample log lines through SensitiveDataFilter and
the real formatters, then assert on what would land in the log file.

Run: venv/bin/python tests/test_log_redaction.py
"""

import io
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import logger as portal_logger  # noqa: E402

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PUB = "pub_Abc123_xyzDEF456ghiJKL"
BARE_PUB = "Abc123_xyzDEF456ghiJKL"
LIVE = "live_Zyx987_wvuTSR654qpoNML"
API_KEY = "portal_" + "0123456789abcdef" * 4


def render(msg, *args, structured=False, exc_info=None, **kw):
    """Return the text the handlers would write for this record."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        portal_logger.StructuredFormatter() if structured
        else logging.Formatter("%(levelname)s %(message)s")
    )
    handler.addFilter(portal_logger.SensitiveDataFilter())
    log = logging.getLogger("test_log_redaction." + str(id(handler)))
    log.propagate = False
    log.setLevel(logging.DEBUG)
    log.addHandler(handler)
    log.info(msg, *args, exc_info=exc_info, **kw)
    return stream.getvalue()


def access(path):
    return f'127.0.0.1 [18/Nov/2026:10:00:00 +0000] "GET {path} HTTP/1.1" 200 512 "-" "UA"'


def test_jwt_in_query_token():
    out = render(access(f"/api/me?token={JWT}&x=1"))
    assert "token=[REDACTED]&x=1" in out, out
    for frag in JWT.split("."):
        assert frag not in out, out


def test_ticket_in_query():
    out = render(access("/ws/chat?ticket=abc123.def456-ghi789&room=1"))
    assert "ticket=[REDACTED]&room=1" in out, out
    assert "abc123" not in out, out


def test_short_token_value():
    out = render(access("/x?token=short"))
    assert "short" not in out and "token=[REDACTED]" in out, out


def test_pub_key_in_hls_path():
    out = render(access(f"/api/stream/{PUB}/hls/index.m3u8"))
    assert PUB not in out and BARE_PUB not in out, out
    assert "/hls/index.m3u8" in out, out


def test_bare_playback_key_in_hls_path():
    out = render(access(f"/api/stream/{BARE_PUB}/hls/index.m3u8"))
    assert BARE_PUB not in out, out


def test_pub_key_in_query_string():
    out = render(access(f"/watch?stream={PUB}&q=1"))
    assert PUB not in out and "&q=1" in out, out


def test_live_key_in_rtmp_url():
    out = render(f"publish from rtmps://example.invalid:1936/live/{LIVE} accepted")
    assert LIVE not in out and "accepted" in out, out


def test_portal_api_key():
    out = render(access(f"/api/foo?key={API_KEY}"))
    assert API_KEY not in out, out
    out = render(f"X-API-Key: {API_KEY}")
    assert API_KEY not in out, out
    out = render("api_key=%s", API_KEY)
    assert API_KEY not in out, out


def test_incoming_webhook_token_in_path():
    tok = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDE"
    line = f'127.0.0.1 [18/Nov/2026:10:00:00 +0000] "POST /api/webhooks/incoming/{tok} HTTP/1.1" 404 10 "-" "UA"'
    out = render(line)
    assert tok not in out and "/api/webhooks/incoming/[REDACTED] HTTP/1.1" in out, out
    out = render(access(f"/api/webhooks/incoming/{tok}?x=1"))
    assert tok not in out and "/api/webhooks/incoming/[REDACTED]?x=1" in out, out
    assert portal_logger.redact(portal_logger.redact(line)) == portal_logger.redact(line)


def test_normal_line_unchanged():
    line = access("/api/streams?limit=20")
    assert render(line) == "INFO " + line + "\n"
    assert render("Invalid token for user alice") == "INFO Invalid token for user alice\n"
    assert render("hook /api/stream/auth ok") == "INFO hook /api/stream/auth ok\n"


def test_args_positional_and_mapping():
    out = render("GET %s", f"/api/me?token={JWT}")
    assert JWT.split(".")[1] not in out, out
    out = render("token=%s", JWT)
    assert JWT.split(".")[2] not in out, out
    out = render("req %(u)s", {"u": f"/a?ticket=zzz999"})
    assert "zzz999" not in out and "ticket=[REDACTED]" in out, out
    out = render("count=%d name=%s", 5, "bob")
    assert out == "INFO count=5 name=bob\n", out


def test_non_string_arg():
    class Boom:
        def __str__(self):
            return f"url /x?token={JWT}"
    out = render("failed: %s", Boom())
    assert JWT.split(".")[0] not in out, out


def test_exception_info():
    try:
        raise ValueError(f"bad url /x?token={JWT} key {LIVE}")
    except ValueError:
        import sys as _s
        exc = _s.exc_info()
    for structured in (False, True):
        out = render("handler failed", exc_info=exc, structured=structured)
        assert "Traceback" in out or structured, out
        assert JWT.split(".")[1] not in out and LIVE not in out, out
        assert "ValueError" in out, out


def test_structured_output_is_json():
    out = render(access(f"/x?token={JWT}"), structured=True)
    data = json.loads(out)
    assert "token=[REDACTED]" in data["message"] and JWT not in out


def test_hls_session_query_value():
    sid = "0b8d6f3e-5c1a-4e7b-9a2d-1f3c5e7a9b0d"
    out = render(access(f"/api/stream/{PUB}/hls/seg0.mp4?session={sid}"))
    assert sid not in out and "session=[REDACTED]" in out, out
    # Line with no other trigger word: the cheap pre-check must still run the rule.
    out = render(f"GET /x/seg.mp4?session={sid}&a=1")
    assert sid not in out and "session=[REDACTED]&a=1" in out, out
    # Ordinary text that merely mentions a session is left alone.
    assert render("user session started") == "INFO user session started\n"


def test_idempotent():
    once = portal_logger.redact(access(f"/api/stream/{PUB}/hls/a.m3u8?token={JWT}"))
    assert portal_logger.redact(once) == once


def test_disabled_setting_passes_through():
    portal_logger.LOG_SETTINGS["filter_sensitive"] = False
    try:
        assert JWT in render(f"token={JWT}")
    finally:
        portal_logger.LOG_SETTINGS["filter_sensitive"] = True


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
