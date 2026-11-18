"""Smoke check: stream thumbnails start one ffmpeg per stream, at most two at a time,
reap a stuck ffmpeg, and run the media programs at lowered priority.

A stage has no ffmpeg and no MediaMTX. The capture therefore runs in-process
(ctx.run_py) through the real request handler and the real stream records in the stage
database, with a fake ffmpeg (a Python script put first on PATH in that process only)
that logs its pid, niceness and arguments and then answers, hangs or fails. The route
itself is also asked over HTTP: an offline stream must answer without starting any
process, and a live stream with no usable MediaMTX (none configured on a fresh stage, none
reachable on a stage from a production copy) must answer 503 with Retry-After.

Needs a phone or a real stream (not provable here): the nice value of the real ffmpeg
processes of a live stream with a relay and a recording (`ps -o pid,ni,cmd -C ffmpeg`).
"""
import json

import aiohttp

PW = "thumbs-owner-pass-1234"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user
import server

async def main():
    await db.connect()
    out = {}
    uid = (await create_user("thumb_owner", %r))["id"]
    for label in ("a", "b", "c", "off"):
        sk = server.generate_stream_key()
        pk = server.generate_public_key()
        sid = await db.create_user_stream(user_id=uid, name="thumb " + label, stream_key=sk,
                                          public_key=pk, is_public=True)
        if label != "off":
            await db.set_stream_live(sid, True)
        out[label] = {"id": sid, "key": sk, "pub": pk}
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
''' % PW

SCENARIOS = r'''
import asyncio, json, os, shutil, signal, stat, subprocess, sys, tempfile, threading, time, types
from unittest import mock
from database import db
import server

KEYS = json.loads(%r)
JPEG = b"\xff\xd8FAKE\xff\xd9"
D = tempfile.mkdtemp(prefix="thumbsmoke_", dir=os.getcwd())

FAKE = """#!%%s
import json, os, sys, time
d = %%r
mode = open(os.path.join(d, "mode")).read().strip()
with open(os.path.join(d, "log"), "a") as f:
    f.write(json.dumps({"pid": os.getpid(), "nice": os.nice(0), "argv": sys.argv[1:]}) + "\\n")
if mode == "hang":
    time.sleep(60)
time.sleep(float(mode.split(":")[1]) if mode.startswith("slow:") else 0.2)
sys.stdout.buffer.write(%%r)
""" %% (sys.executable, D, JPEG)
with open(os.path.join(D, "ffmpeg"), "w") as f:
    f.write(FAKE)
os.chmod(os.path.join(D, "ffmpeg"), 0o755)
os.environ["PATH"] = D + os.pathsep + os.environ["PATH"]


def mode(m):
    with open(os.path.join(D, "mode"), "w") as f:
        f.write(m)


def log():
    p = os.path.join(D, "log")
    return [json.loads(x) for x in open(p).read().splitlines()] if os.path.exists(p) else []


def reset():
    server._thumbnail_cache.clear()
    if os.path.exists(os.path.join(D, "log")):
        os.remove(os.path.join(D, "log"))


async def get(key):
    r = await server.http_stream_thumbnail(types.SimpleNamespace(match_info={"stream_key": key}))
    return r


async def main():
    await db.connect()
    server.db = db
    async def mtx():
        return {"hls_port": 8888}
    server._get_mediamtx_config = mtx
    out = {}
    a, b, c = KEYS["a"]["key"], KEYS["b"]["key"], KEYS["c"]["key"]

    # the nice/ionice probe must not block the event loop: note where subprocess.run runs
    loop_thread = threading.get_ident()
    probe_threads = []
    real_run = subprocess.run
    def spy_run(*a_, **kw):
        probe_threads.append(threading.get_ident())
        return real_run(*a_, **kw)
    server.subprocess.run = spy_run

    # 1. twenty concurrent requests for one cold thumbnail (public and private key mixed)
    reset(); mode("slow:1")
    keys = [a, KEYS["a"]["pub"]] * 10
    rs = await asyncio.gather(*[get(k) for k in keys])
    out["flight_status"] = sorted(set(r.status for r in rs))
    out["flight_same_body"] = all(r.body == JPEG for r in rs)
    out["flight_spawns"] = len(log())
    # 2. priority of the running ffmpeg
    out["nice_seen"] = log()[0]["nice"] if log() else None
    out["nice_base"] = os.nice(0)
    out["argv"] = log()[0]["argv"] if log() else None

    # 3. forced timeout: killed and reaped
    reset(); mode("hang")
    server._THUMBNAIL_TIMEOUT = 0.5
    rs = await asyncio.gather(*[get(a) for _ in range(5)])
    out["timeout_status"] = sorted(set(r.status for r in rs))
    out["timeout_retry_after"] = sorted(set(r.headers.get("Retry-After") or "" for r in rs))
    lg = log()
    out["timeout_spawns"] = len(lg)
    out["timeout_pid_left"] = os.path.exists("/proc/%%d" %% lg[0]["pid"]) if lg else None
    server._THUMBNAIL_TIMEOUT = 10

    # 4. saturation: two captures running, a third stream is refused or gets the stale frame
    reset(); mode("slow:1")
    ta = asyncio.ensure_future(get(a)); tb = asyncio.ensure_future(get(b))
    await asyncio.sleep(0.4)
    r = await get(c)
    out["sat_status"] = r.status
    out["sat_retry_after"] = r.headers.get("Retry-After")
    out["sat_spawns"] = len(log())
    server._thumbnail_cache[c] = (time.time() - 100, b"STALE")
    r = await get(c)
    out["sat_stale_status"], out["sat_stale_body"] = r.status, r.body.decode()
    out["sat_spawns_after_stale"] = len(log())
    # a frame older than 5 minutes is not served: 503 again, and it is dropped
    server._thumbnail_cache[c] = (time.time() - 301, b"ANCIENT")
    r = await get(c)
    out["sat_ancient_status"], out["sat_ancient_dropped"] = r.status, c not in server._thumbnail_cache
    await ta; await tb

    out["probe_runs"] = len(probe_threads)
    out["probe_on_loop"] = loop_thread in probe_threads
    out["inflight_left"] = len(server._thumbnail_inflight)
    out["slots_free"] = server._thumbnail_sem._value
    # nothing of the fake ffmpeg may still be running or waiting to be reaped
    left = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                cmd = open("/proc/%%s/cmdline" %% pid, "rb").read().decode(errors="replace")
            except OSError:
                continue
            if D in cmd:
                left.append(pid)
    out["procs_left"] = left
    await db.close()
    print("RESULT " + json.dumps(out))

def cleanup():
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if D in open("/proc/%%s/cmdline" %% pid, "rb").read().decode(errors="replace"):
                    os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
    shutil.rmtree(D, ignore_errors=True)


try:
    asyncio.run(main())
finally:
    cleanup()
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("no RESULT line in: " + out[-600:])


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    if rc != 0:
        ctx.ok("thumbs: staged user and streams created", False, out[-300:])
        return
    keys = _result(out)

    rc, out = await ctx.run_py(SCENARIOS % json.dumps(keys), timeout=90)
    if rc != 0:
        ctx.ok("thumbs: scenarios ran", False, out[-500:])
        return
    r = _result(out)

    ctx.ok("thumbs: 20 concurrent requests for one cold thumbnail all succeed with the same frame",
           r["flight_status"] == [200] and r["flight_same_body"], str(r["flight_status"]))
    ctx.ok("thumbs: ... and spawn exactly one ffmpeg", r["flight_spawns"] == 1, f"spawned {r['flight_spawns']}")
    ctx.ok("thumbs: the ffmpeg arguments are unchanged",
           r["argv"] is not None and r["argv"][:3] == ["-y", "-i", "https://127.0.0.1:8888/live/" + keys["a"]["key"] + "/index.m3u8"]
           and r["argv"][-1] == "pipe:1", str(r["argv"]))
    ctx.ok("thumbs: the running ffmpeg has nice 10 (relative to the portal's own)",
           r["nice_seen"] is not None and r["nice_seen"] == r["nice_base"] + 10,
           f"seen {r['nice_seen']}, portal {r['nice_base']}")
    ctx.ok("thumbs: after a forced timeout every waiting request gets 503 with Retry-After and one ffmpeg ran",
           r["timeout_status"] == [503] and r["timeout_retry_after"] != [""] and "" not in r["timeout_retry_after"]
           and r["timeout_spawns"] == 1,
           f"{r['timeout_status']} {r['timeout_retry_after']} spawns {r['timeout_spawns']}")
    ctx.ok("thumbs: after a forced timeout the ffmpeg is gone from /proc (no orphan, no zombie)",
           r["timeout_pid_left"] is False, str(r["timeout_pid_left"]))
    ctx.ok("thumbs: with two captures running a third stream gets 503 with Retry-After and starts nothing",
           r["sat_status"] == 503 and r["sat_retry_after"] and r["sat_spawns"] == 2,
           f"{r['sat_status']} Retry-After={r['sat_retry_after']} spawns={r['sat_spawns']}")
    ctx.ok("thumbs: with two captures running a cached stale frame is served instead",
           r["sat_stale_status"] == 200 and r["sat_stale_body"] == "STALE" and r["sat_spawns_after_stale"] == 2,
           f"{r['sat_stale_status']} {r['sat_stale_body']}")
    ctx.ok("thumbs: with two captures running a frame older than 5 minutes is not served (503, frame dropped)",
           r["sat_ancient_status"] == 503 and r["sat_ancient_dropped"] is True,
           f"{r['sat_ancient_status']} dropped={r['sat_ancient_dropped']}")
    ctx.ok("thumbs: the nice/ionice probe ran off the event loop thread",
           r["probe_runs"] > 0 and r["probe_on_loop"] is False, f"runs={r['probe_runs']} on_loop={r['probe_on_loop']}")
    ctx.ok("thumbs: no capture stays registered, both slots are free and no fake ffmpeg process is left",
           r["inflight_left"] == 0 and r["slots_free"] == 2 and r["procs_left"] == [],
           f"inflight={r['inflight_left']} slots={r['slots_free']} procs={r['procs_left']}")

    # The route itself, on the running stage
    async with ctx.http() as s:
        async with s.get(f"{ctx.base_url}/api/stream/{keys['off']['pub']}/thumbnail", allow_redirects=False) as resp:
            ctx.ok("thumbs: HTTP: an offline stream without a custom thumbnail is 404", resp.status == 404, str(resp.status))
        async with s.get(f"{ctx.base_url}/api/stream/live_doesnotexist/thumbnail") as resp:
            ctx.ok("thumbs: HTTP: an unknown key is 403", resp.status == 403, str(resp.status))
        async with s.get(f"{ctx.base_url}/api/stream/{keys['a']['pub']}/thumbnail") as resp:
            body = await resp.text()
            # A fresh stage has no MediaMTX settings (503 "not configured"). A stage started
            # from a production database copy has them, but nothing it can reach serves this
            # stream, so the capture fails or times out: also 503. Either way a temporary
            # answer with Retry-After, never 500, 504 or a hang.
            ctx.ok("thumbs: HTTP: a live stream on a stage without a usable MediaMTX is 503 with Retry-After, not a hang, 500 or 504",
                   resp.status == 503 and bool(resp.headers.get("Retry-After")),
                   f"{resp.status} Retry-After={resp.headers.get('Retry-After')} {body[:80]}")

        # Stream cards retry a failed thumbnail (2 s, 4 s, 8 s) through one shared script
        async with s.get(f"{ctx.base_url}/static/js/stream-thumb.js?v=1") as resp:
            js = await resp.text()
            ctx.ok("thumbs: HTTP: the shared thumbnail retry script is served with the 2/4/8 s delays",
                   resp.status == 200 and "[2000, 4000, 8000]" in js and "window.thumbError" in js, str(resp.status))
        for page in ("live.html", "streams.html"):
            async with s.get(f"{ctx.base_url}/static/{page}") as resp:
                html = await resp.text()
                ctx.ok(f"thumbs: HTTP: {page} loads stream-thumb.js and its cards call thumbError, no inline placeholder code",
                       resp.status == 200 and "/static/js/stream-thumb.js?v=1" in html
                       and 'onerror="thumbError(this)"' in html and "this.nextElementSibling" not in html,
                       str(resp.status))
