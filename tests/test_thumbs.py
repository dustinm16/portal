"""Thumbnail capture: one ffmpeg per stream at a time, at most two at once, a stuck
ffmpeg is killed and reaped, and the media programs run at lowered priority.

A fake ffmpeg (a small Python script on PATH) stands in for the real one: it logs its
pid, niceness and arguments, then answers, hangs or fails depending on a mode file.

Run: venv/bin/python tests/test_thumbs.py
"""

import asyncio
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import tempfile
import time
import types
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402

JPEG = b"\xff\xd8FAKE-JPEG\xff\xd9"

FAKE_FFMPEG = '''#!%(py)s
import json, os, subprocess, sys, time
d = %(dir)r
mode = open(os.path.join(d, "mode")).read().strip()
try:
    io = subprocess.run(["ionice", "-p", str(os.getpid())], capture_output=True, text=True).stdout.strip()
except OSError:
    io = ""
with open(os.path.join(d, "log"), "a") as f:
    f.write(json.dumps({"pid": os.getpid(), "nice": os.nice(0), "io": io, "argv": sys.argv[1:]}) + "\\n")
if mode == "hang":
    time.sleep(300)
elif mode == "fail":
    sys.stderr.write("fake ffmpeg failure\\n")
    sys.exit(1)
else:
    time.sleep(float(mode.split(":")[1]) if mode.startswith("slow:") else 0.2)
    sys.stdout.buffer.write(%(jpeg)r)
'''


def reset_media_cache():
    server._media_prefix_ok.clear()
    server._media_which_cache.clear()
    server._media_warmed = False


class Env:
    """A temp dir with the fake ffmpeg first on PATH, three live streams and clean module state."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="thumbtest_")
        d = self.tmp.name
        self.dir = d
        exe = Path(d) / "ffmpeg"
        exe.write_text(FAKE_FFMPEG % {"py": sys.executable, "dir": d, "jpeg": JPEG})
        exe.chmod(0o755)
        self.mode("0.2")
        self.old_path = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + self.old_path
        reset_media_cache()
        server._thumbnail_cache.clear()
        self.streams = {}
        for i, name in enumerate(("live_aaa", "live_bbb", "live_ccc"), start=1):
            self.streams[name] = {"id": i, "stream_key": name, "is_live": 1}

        async def validate(key, require_publish=False, request=None):
            s = self.streams.get(key)
            return (s, "") if s else (None, "Invalid stream key")

        async def mtx():
            return {"hls_port": 8888}

        self.patches = [
            mock.patch.object(server, "_validate_stream_access", validate),
            mock.patch.object(server, "_get_mediamtx_config", mtx),
        ]
        for p in self.patches:
            p.start()

    def mode(self, value):
        Path(self.dir, "mode").write_text(value)

    def log(self):
        p = Path(self.dir, "log")
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    async def get(self, key):
        return await server.http_stream_thumbnail(types.SimpleNamespace(match_info={"stream_key": key}))

    def close(self):
        for p in self.patches:
            p.stop()
        os.environ["PATH"] = self.old_path
        server._thumbnail_cache.clear()
        reset_media_cache()
        self.tmp.cleanup()


def run(coro_fn):
    env = Env()
    try:
        asyncio.run(coro_fn(env))
        assert not server._thumbnail_inflight, "a capture was left registered"
        assert not server._thumbnail_sem.locked() and server._thumbnail_sem._value == server._THUMBNAIL_MAX_CAPTURES, \
            "a semaphore slot was not given back"
    finally:
        env.close()


def gone(pid):
    """True when the pid is neither running nor a zombie waiting to be reaped."""
    return not os.path.exists(f"/proc/{pid}")


async def wait_gone(pid, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if gone(pid):
            return True
        await asyncio.sleep(0.05)
    return gone(pid)


def test_twenty_cold_requests_spawn_one_ffmpeg():
    async def body(env):
        env.mode("slow:1")
        rs = await asyncio.gather(*[env.get("live_aaa") for _ in range(20)])
        assert [r.status for r in rs] == [200] * 20, [r.status for r in rs]
        assert all(r.body == JPEG for r in rs)
        assert len(env.log()) == 1, env.log()
        # now cached: no new process
        r = await env.get("live_aaa")
        assert r.status == 200 and len(env.log()) == 1
    run(body)


def test_ffmpeg_command_keeps_its_arguments():
    async def body(env):
        r = await env.get("live_aaa")
        assert r.status == 200
        argv = env.log()[0]["argv"]
        assert argv == ["-y", "-i", "https://127.0.0.1:8888/live/live_aaa/index.m3u8", "-vframes", "1",
                        "-f", "image2", "-vcodec", "mjpeg", "-q:v", "3", "-vf", "scale=640:-1", "pipe:1"], argv
    run(body)


def test_running_ffmpeg_has_nice_10_and_idle_io_class():
    async def body(env):
        await env.get("live_aaa")
        rec = env.log()[0]
        assert rec["nice"] == os.nice(0) + server._MEDIA_NICE == os.nice(0) + 10, rec
        if shutil.which("ionice"):
            assert "idle" in rec["io"], rec
    run(body)


def test_nice_wrapper_keeps_the_process_id():
    async def body(env):
        env.mode("slow:1")
        proc_pid = {}
        real = asyncio.create_subprocess_exec

        async def spy(*a, **k):
            p = await real(*a, **k)
            proc_pid["pid"] = p.pid
            return p
        with mock.patch.object(server.asyncio, "create_subprocess_exec", spy):
            await env.get("live_aaa")
        assert env.log()[0]["pid"] == proc_pid["pid"]
    run(body)


def test_timeout_kills_and_reaps_ffmpeg():
    async def body(env):
        env.mode("hang")
        with mock.patch.object(server, "_THUMBNAIL_TIMEOUT", 0.5):
            rs = await asyncio.gather(*[env.get("live_aaa") for _ in range(5)])
        assert [r.status for r in rs] == [503] * 5, [r.status for r in rs]
        assert all(r.headers.get("Retry-After") == str(server._THUMBNAIL_RETRY_AFTER) for r in rs)
        log = env.log()
        assert len(log) == 1, log
        assert gone(log[0]["pid"]), "ffmpeg is still there (running or zombie)"
    run(body)


def test_timeout_serves_the_stale_frame():
    async def body(env):
        env.mode("hang")
        server._thumbnail_cache["live_aaa"] = (time.time() - 100, b"OLD")
        with mock.patch.object(server, "_THUMBNAIL_TIMEOUT", 0.3):
            r = await env.get("live_aaa")
        assert r.status == 200 and r.body == b"OLD"
        assert r.headers["Cache-Control"] == "private, max-age=5"  # a stream that is not an open share link
        assert gone(env.log()[0]["pid"])
    run(body)


def test_failed_capture_is_503_or_stale_and_slot_returns():
    async def body(env):
        env.mode("fail")
        r = await env.get("live_aaa")
        assert r.status == 503 and r.headers["Retry-After"] == str(server._THUMBNAIL_RETRY_AFTER), (r.status, r.headers)
        server._thumbnail_cache["live_aaa"] = (time.time() - 100, b"OLD")
        r = await env.get("live_aaa")
        assert r.status == 200 and r.body == b"OLD"
    run(body)


def test_cancelling_the_capture_kills_ffmpeg():
    async def body(env):
        env.mode("hang")
        req = asyncio.ensure_future(env.get("live_aaa"))
        for _ in range(100):
            await asyncio.sleep(0.05)
            if env.log():
                break
        pid = env.log()[0]["pid"]
        assert not gone(pid)
        task = server._thumbnail_inflight["live_aaa"]
        task.cancel()
        try:
            await req
        except asyncio.CancelledError:
            pass
        assert await wait_gone(pid), "ffmpeg survived a cancelled capture"
    run(body)


def test_a_departing_client_does_not_cancel_the_shared_capture():
    async def body(env):
        env.mode("slow:1")
        first = asyncio.ensure_future(env.get("live_aaa"))
        second = asyncio.ensure_future(env.get("live_aaa"))
        await asyncio.sleep(0.3)
        first.cancel()
        r = await second
        assert r.status == 200 and r.body == JPEG
        assert len(env.log()) == 1
    run(body)


def test_saturated_gives_503_with_retry_after_or_stale_frame():
    async def body(env):
        env.mode("slow:1")
        a = asyncio.ensure_future(env.get("live_aaa"))
        b = asyncio.ensure_future(env.get("live_bbb"))
        await asyncio.sleep(0.3)
        assert len(env.log()) == 2
        r = await env.get("live_ccc")
        assert r.status == 503 and r.headers["Retry-After"] == str(server._THUMBNAIL_RETRY_AFTER), (r.status, r.headers)
        assert len(env.log()) == 2, "a third ffmpeg was started"
        server._thumbnail_cache["live_ccc"] = (time.time() - 100, b"OLD-C")
        r = await env.get("live_ccc")
        assert r.status == 200 and r.body == b"OLD-C" and len(env.log()) == 2
        # a request for a stream already being captured joins it, even while saturated
        j = await env.get("live_aaa")
        assert j.status == 200 and j.body == JPEG
        assert (await a).status == 200 and (await b).status == 200
        # slots are free again
        server._thumbnail_cache.pop("live_ccc", None)
        r = await env.get("live_ccc")
        assert r.status == 200 and len(env.log()) == 3
    run(body)


def test_missing_mediamtx_config_is_503_and_starts_nothing():
    async def body(env):
        async def none():
            return {}
        with mock.patch.object(server, "_get_mediamtx_config", none):
            r = await env.get("live_aaa")
        assert r.status == 503 and not env.log()
        assert r.headers["Retry-After"] == str(server._THUMBNAIL_RETRY_AFTER)
    run(body)


def test_invalid_key_and_offline_stream_do_not_start_ffmpeg():
    async def body(env):
        assert (await env.get("live_zzz")).status == 404
        env.streams["live_aaa"]["is_live"] = 0
        assert (await env.get("live_aaa")).status == 404
        assert not env.log()
    run(body)


def _argv_env(path_dir=None):
    return mock.patch.dict(os.environ, {"PATH": path_dir} if path_dir is not None else {})


def test_media_exec_argv_prefix_and_order():
    reset_media_cache()
    cmd = ["ffmpeg", "-hide_banner", "-i", "in", "-c", "copy", "-f", "flv", "-x", "y", "rtmp://h/app/k"]
    with tempfile.TemporaryDirectory() as d:
        Path(d, "ffmpeg").write_text("#!/bin/sh\n")
        Path(d, "ffmpeg").chmod(0o755)
        with _argv_env(d + os.pathsep + os.environ["PATH"]):
            idle = server._media_exec_argv(cmd, "idle")
            rec = server._media_exec_argv(cmd, "best_effort")
    assert idle[-len(cmd):] == cmd and rec[-len(cmd):] == cmd, "the command must come last and unchanged"
    assert idle[1:3] == ["-n", "10"] and idle[0].endswith("nice"), idle
    assert idle[3].endswith("ionice") and idle[4:5] == ["-c3"], idle
    assert rec[3].endswith("ionice") and rec[4:6] == ["-c2", "-n7"], rec
    assert len(idle) == len(cmd) + 5 and len(rec) == len(cmd) + 6


def test_media_exec_argv_without_nice_or_ionice_is_the_bare_command():
    reset_media_cache()
    with tempfile.TemporaryDirectory() as d:
        Path(d, "ffmpeg").write_text("#!/bin/sh\n")
        Path(d, "ffmpeg").chmod(0o755)
        with _argv_env(d):   # no nice, no ionice here
            assert server._media_exec_argv(["ffmpeg", "-i", "x"]) == ["ffmpeg", "-i", "x"]
        # only ionice missing
        os.symlink(shutil.which("nice"), os.path.join(d, "nice"))
        os.symlink(shutil.which("true"), os.path.join(d, "true"))
        reset_media_cache()
        with _argv_env(d):
            out = server._media_exec_argv(["ffmpeg", "-i", "x"], "idle")
        assert out[1:3] == ["-n", "10"] and out[3:] == ["ffmpeg", "-i", "x"], out


def test_media_exec_argv_skips_an_ionice_that_does_not_work():
    reset_media_cache()
    with tempfile.TemporaryDirectory() as d:
        for name, text in (("ffmpeg", "#!/bin/sh\n"), ("ionice", "#!/bin/sh\nexit 1\n")):
            Path(d, name).write_text(text)
            Path(d, name).chmod(0o755)
        os.symlink(shutil.which("nice"), os.path.join(d, "nice"))
        os.symlink(shutil.which("true"), os.path.join(d, "true"))
        with _argv_env(d):
            out = server._media_exec_argv(["ffmpeg", "-i", "x"], "idle")
    assert "ionice" not in " ".join(out) and out[1:3] == ["-n", "10"], out


def test_missing_program_still_raises_file_not_found():
    reset_media_cache()

    async def go():
        with _argv_env("/nonexistent-dir"):
            assert server._media_exec_argv(["ffmpeg", "-i", "x"]) == ["ffmpeg", "-i", "x"]
            try:
                await server._media_exec(["ffmpeg", "-i", "x"])
            except FileNotFoundError:
                return True
        return False
    assert asyncio.run(go()), "a missing ffmpeg must raise FileNotFoundError, not exit 127 behind nice"


def test_saturated_503_when_the_only_cached_frame_is_older_than_five_minutes():
    async def body(env):
        env.mode("slow:1")
        a = asyncio.ensure_future(env.get("live_aaa"))
        b = asyncio.ensure_future(env.get("live_bbb"))
        await asyncio.sleep(0.3)
        assert server._THUMBNAIL_STALE_MAX == 300
        server._thumbnail_cache["live_ccc"] = (time.time() - 301, b"TOO-OLD")
        r = await env.get("live_ccc")
        assert r.status == 503 and r.headers["Retry-After"] == str(server._THUMBNAIL_RETRY_AFTER), (r.status, r.body)
        assert "live_ccc" not in server._thumbnail_cache, "an expired frame must be dropped"
        server._thumbnail_cache["live_ccc"] = (time.time() - 299, b"JUST-OK")
        r = await env.get("live_ccc")
        assert r.status == 200 and r.body == b"JUST-OK"
        await a
        await b
    run(body)


def test_failed_capture_does_not_serve_a_frame_older_than_five_minutes():
    async def body(env):
        env.mode("fail")
        server._thumbnail_cache["live_aaa"] = (time.time() - 400, b"TOO-OLD")
        r = await env.get("live_aaa")
        assert r.status == 503 and r.headers["Retry-After"] == str(server._THUMBNAIL_RETRY_AFTER), (r.status, r.body)
    run(body)


def test_a_capture_keeps_other_frames_that_the_stale_fallback_can_still_serve():
    async def body(env):
        server._thumbnail_cache["live_bbb"] = (time.time() - 100, b"STALE-BUT-SERVABLE")
        server._thumbnail_cache["live_ccc"] = (time.time() - 301, b"TOO-OLD")
        r = await env.get("live_aaa")           # a fresh capture, which prunes the cache
        assert r.status == 200
        assert server._thumbnail_cache["live_bbb"][1] == b"STALE-BUT-SERVABLE", "pruned before the stale limit"
        assert "live_ccc" not in server._thumbnail_cache, "a frame past the stale limit was kept"
        # the fallback still works for that stream after another stream's capture
        env.mode("fail")
        r = await env.get("live_bbb")
        assert r.status == 200 and r.body == b"STALE-BUT-SERVABLE"
    run(body)


def test_media_probe_runs_in_a_thread_once_and_which_is_cached():
    async def body(env):
        loop_thread = threading.get_ident()
        real_run, real_which = subprocess.run, shutil.which
        runs, whichs = [], []

        def spy_run(*a, **kw):
            runs.append(threading.get_ident())
            return real_run(*a, **kw)

        def spy_which(name, *a, **kw):
            whichs.append(name)
            return real_which(name, *a, **kw)

        with mock.patch.object(server.subprocess, "run", spy_run), mock.patch.object(server.shutil, "which", spy_which):
            assert (await env.get("live_aaa")).status == 200
            assert runs, "the probe never ran"
            assert all(t != loop_thread for t in runs), "subprocess.run ran on the event loop thread"
            n_runs = len(runs)
            whichs.clear()
            for _ in range(3):
                proc = await server._media_exec(["ffmpeg", "-version"], "best_effort",
                                                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await proc.wait()
            assert len(runs) == n_runs, "a later spawn probed again"
            assert not {"nice", "ionice", "true"} & set(whichs), whichs
    run(body)


def test_startup_warms_the_probes_off_the_loop():
    src = Path(server.__file__).read_text()
    assert "await asyncio.to_thread(_media_warm)" in src
    assert src.count("await asyncio.to_thread(_media_warm)") == 2   # startup and first spawn
    reset_media_cache()
    server._media_warm()
    assert server._media_warmed
    if shutil.which("nice"):
        assert any(k[1:3] == ("-n", "10") for k in server._media_prefix_ok), server._media_prefix_ok


NODE_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const timers = []; let clock = 1000;
const mk = (src) => ({
  dataset: {}, style: {}, isConnected: true, _src: src,
  getAttribute(n) { return n === 'src' ? this._src : null; },
  set src(v) { this._src = v; }, get src() { return this._src; },
  nextElementSibling: { style: { display: 'none' } },
});
const ctx = { window: {}, URL, setTimeout: (f, ms) => { timers.push([f, ms]); return 1; },
              parseInt, String, Date: { now: () => (clock += 2000) } };
ctx.window.location = { href: 'https://portal.test/live' };
ctx.window.window = ctx.window;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx);
const out = {};
const img = mk('/api/stream/pub_x/thumbnail?t=1');
const fire = () => { const [f, ms] = timers.shift(); const d = ms; f(); return d; };
const delays = [], srcs = [];
for (let i = 0; i < 3; i++) {
  ctx.window.thumbError(img);
  out['placeholder_after_error_' + (i + 1)] = img.nextElementSibling.style.display;
  delays.push(fire()); srcs.push(img.src);
}
ctx.window.thumbError(img);
out.delays = delays; out.srcs = srcs;
out.timers_after_fourth = timers.length;
out.final_placeholder = img.nextElementSibling.style.display;
out.final_img = img.style.display;
// a card that left the page is not retried
const gone = mk('/a?t=1'); ctx.window.thumbError(gone); gone.isConnected = false; fire();
out.gone_src = gone.src;
// an absolute URL keeps its host
const ext = mk('https://cdn.test/x.jpg?q=1'); ctx.window.thumbError(ext); fire();
out.ext = ext.src;
console.log(JSON.stringify(out));
"""


def test_card_thumbnail_retries_three_times_then_shows_the_placeholder():
    js = Path(server.__file__).parent / "static" / "js" / "stream-thumb.js"
    assert js.exists()
    if not shutil.which("node"):
        print("     (node not installed: behaviour part skipped)")
        return
    out = subprocess.run(["node", "-e", NODE_HARNESS, str(js)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert r["delays"] == [2000, 4000, 8000], r
    for i in (1, 2, 3):
        assert r["placeholder_after_error_%d" % i] == "none", "placeholder shown before the retries ran out"
    assert len(set(r["srcs"])) == 3 and all(s.startswith("https://portal.test/api/stream/pub_x/thumbnail?t=1&r=") for s in r["srcs"]), r["srcs"]
    assert r["timers_after_fourth"] == 0 and r["final_placeholder"] == "flex" and r["final_img"] == "none", r
    assert r["gone_src"] == "/a?t=1", r
    assert r["ext"].startswith("https://cdn.test/x.jpg?q=1&r="), r


def test_both_stream_pages_use_the_shared_retry_and_no_inline_handler_body():
    root = Path(server.__file__).parent / "static"
    for page in ("live.html", "streams.html"):
        html = (root / page).read_text()
        assert '<script src="/static/js/stream-thumb.js?v=1"></script>' in html, page
        assert 'onerror="thumbError(this)"' in html, page
        assert "this.nextElementSibling" not in html, page + ": inline placeholder code is back"
        assert html.index("stream-thumb.js") < html.index("thumbError(this)"), page


def test_all_four_ffmpeg_sites_use_the_helper_and_mediamtx_does_not():
    src = Path(server.__file__).read_text()
    assert src.count("asyncio.create_subprocess_exec(") == 1, "only _media_exec may spawn directly"
    assert src.count("await _media_exec(") == 3 + 1   # recording, relay start, relay restart, thumbnail
    assert 'cmd, "best_effort"' in src
    assert src.count('cmd, "idle"') == 2
    for p in (Path(server.__file__).parent / "services").glob("*.py"):
        assert "_media_exec" not in p.read_text(), p


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
