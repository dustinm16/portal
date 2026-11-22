"""VOD disk guard: free-space and backlog limits for the recorder.

A real ffmpeg records a generated clip (read at its own speed, standing in for the stream)
into 2-second MKV chunks in a temporary staging folder; the SFTP target is blocked, so no
chunk can leave. Writes well under a megabyte, inside a temporary directory.

Run: venv/bin/python tests/test_vod_guard.py
"""
import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import alerts  # noqa: E402
import outbound_guard  # noqa: E402
import vod_staging as vs  # noqa: E402

outbound_guard.install()
vs.TEMP_ROOTS = ()  # the sandboxes below live under /tmp

import server  # noqa: E402

from test_vod_guard_stop import check_chunks, children_of_this_process, make_clip  # noqa: E402


class FakeDb:
    def __init__(self, settings=None):
        self.settings = dict(settings or {})
        self.activity = []

    async def get_setting(self, key):
        return self.settings.get(key)

    async def get_vod_storage(self, uid):
        return {"remote_path": "/v", "host": "h", "port": 22}

    async def get_user_by_id(self, uid):
        return {"id": uid, "username": "owner"}

    async def log_activity(self, user_id, name, action, detail):
        self.activity.append((user_id, action, detail))


class Env:
    """Patches the server module so one real ffmpeg records a local clip into a temp folder."""

    extra_input = []

    def __init__(self, t, settings):
        self.t = t
        self.stage = os.path.join(t, "stage")
        self.db = FakeDb(settings)
        self.fired = []
        self.clip = os.path.join(t, "src.mp4")
        make_clip(self.clip)

    async def fire(self, event, payload):
        self.fired.append((event, payload))
        return 1

    async def notify(self, event, title, summary):
        pass

    async def blocked(self, uid):
        return None, None, "Connection failed"

    async def mtx(self):
        return {"x": 1}

    def __enter__(self):
        alerts.reset_state()
        alerts.bind(fire=self.fire, notify=self.notify)
        server._vod_guard_state.clear()
        self.patches = [
            mock.patch.object(server, "VOD_TEMP_DIR", self.stage),
            mock.patch.object(server, "_PROJECT_ROOT", os.path.join(self.t, "project")),
            mock.patch.object(server, "db", self.db),
            mock.patch.object(server, "_get_mediamtx_config", self.mtx),
            mock.patch.object(server, "_connect_vod_sftp", self.blocked),
            mock.patch.object(server, "_vod_staging_usable", True),
            mock.patch.object(server, "VOD_SEGMENT_DURATION", 2),
            mock.patch.object(server, "VOD_UPLOAD_TICK", 0.5),
            mock.patch.object(server, "_vod_input_args",
                              lambda url: self.extra_input + ["-re", "-stream_loop", "-1", "-i", self.clip]),
        ]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *a):
        for rec in list(server.active_recordings.values()):
            proc = rec.get("process")
            if proc is not None and proc.returncode is None:
                proc.kill()
        server.active_recordings.clear()
        for p in reversed(self.patches):
            p.stop()
        alerts.unbind()
        alerts.reset_state()

    def start(self, stream_id=9):
        return server.start_vod_recording(
            {"id": stream_id, "user_id": 7, "name": "My Show", "owner_username": "owner"}, "live_x")

    def alerts_sent(self):  # noqa: D401
        return [e for e, _ in self.fired if e == "vod.recording_stopped"]


async def wait_until(cond, seconds):
    end = asyncio.get_event_loop().time() + seconds
    while asyncio.get_event_loop().time() < end:
        if cond():
            return True
        await asyncio.sleep(0.2)
    return cond()


def test_backlog_limit_stops_the_recording_cleanly_with_one_alert():
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        # 0.00005 GB is about 52 KB: two completed 2-second chunks exceed it
        env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0.00005"})

        async def go():
            with env:
                await env.start()
                rec = server.active_recordings[9]
                process = rec["process"]
                session_dir = rec["session_dir"]
                assert await wait_until(lambda: 9 not in server.active_recordings, 25), "not stopped"
                await asyncio.sleep(1.0)
                return process.returncode, session_dir, env.alerts_sent(), dict(server._vod_guard_state), \
                    list(env.db.activity)

        rc, session_dir, sent, state, activity = asyncio.run(go())
        assert rc == 0, rc  # ended by "q", not by a signal
        # the chunks are still here (the target is blocked) and the last one is a complete file
        chunks = check_chunks(session_dir, 2)
        assert vs.read_sidecar(session_dir) is not None
        assert sent == ["vod.recording_stopped"], sent   # one alert, however many ticks
        assert state[7]["kind"] == "stopped" and state[7]["code"] in ("session_backlog", "total_backlog"), state
        assert "waiting to be uploaded" in state[7]["message"]
        assert [a for a in activity if a[1] == "vod_stopped"], activity
        assert os.path.basename(chunks[-1]).startswith("chunk_")
    assert children_of_this_process() == []


def test_a_recording_running_normally_is_left_alone_and_low_free_space_stops_it_once():
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})  # both checks off

        async def go():
            with env:
                await env.start()
                rec = server.active_recordings[9]
                await asyncio.sleep(3.5)  # several ticks, completed chunks piling up (target blocked)
                assert 9 in server.active_recordings and rec["process"].returncode is None
                assert env.alerts_sent() == [] and 7 not in server._vod_guard_state
                # the owner of the machine raises the floor above what is free: the next tick stops it
                env.db.settings["vod_min_free_gb"] = "1000000"
                assert await wait_until(lambda: 9 not in server.active_recordings, 25), "not stopped"
                await asyncio.sleep(1.0)
                return rec["process"].returncode, rec["session_dir"], env.alerts_sent(), dict(server._vod_guard_state)

        rc, session_dir, sent, state = asyncio.run(go())
        assert rc == 0, rc
        check_chunks(session_dir, 2)
        assert sent == ["vod.recording_stopped"], sent
        assert state[7]["code"] == "low_free_space" and "free" in state[7]["message"], state
    assert children_of_this_process() == []


def test_a_new_recording_is_refused_with_the_reason_and_one_alert():
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        env = Env(t, {"vod_min_free_gb": "1000000"})

        async def go():
            with env:
                await env.start()
                await env.start()          # the streamer reconnects: refused again
                await asyncio.sleep(0.5)
                return (9 in server.active_recordings, env.alerts_sent(), dict(server._vod_guard_state),
                        list(env.db.activity), server._vod_guard_public(7))

        running, sent, state, activity, public = asyncio.run(go())
        assert not running
        assert sent == ["vod.recording_stopped"], sent   # one per stream and reason
        assert state[7]["kind"] == "refused" and state[7]["code"] == "low_free_space"
        assert public["kind"] == "refused" and set(public) == {"kind", "code", "message", "stream_name", "at"}
        assert all("/" not in v for v in (public["message"],)) or "staging folder" in public["message"]
        assert [a for a in activity if a[1] == "vod_skipped" and "was not started" in a[2]], activity
        payload = env.fired[0][1]
        assert "My Show" in str(payload["details"]), "the generic format names the stream"
        assert "third_party" in payload and "My Show" not in str(payload["third_party"]), \
            "a private stream's name must stay out of the ntfy, Gotify, Discord and Slack formats"
        assert [n for n in os.listdir(env.stage) if n != vs.MARKER_NAME] == [], "a refused start made a folder"


def test_total_backlog_of_other_folders_refuses_a_start():
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0.00001"})  # about 10 KB
        vs.ensure_private_dir(env.stage)
        os.makedirs(os.path.join(env.stage, "1_2026-01-01_1"))
        Path(env.stage, "1_2026-01-01_1", "chunk_000.mkv").write_bytes(b"x" * 20000)

        async def go():
            with env:
                await env.start()
                return dict(server._vod_guard_state)

        state = asyncio.run(go())
        assert state[7]["kind"] == "refused" and state[7]["code"] == "total_backlog", state


def test_zero_switches_both_checks_off():
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})

        async def go():
            with env:
                await env.start()
                ok = 9 in server.active_recordings
                rec = server.active_recordings.get(9)
                await server.stop_vod_recording(9, force=True)
                return ok, rec

        ok, rec = asyncio.run(go())
        assert ok and 7 not in server._vod_guard_state


def test_limits_come_from_the_settings_with_the_owner_defaults():
    async def go():
        with mock.patch.object(server, "db", FakeDb({})):
            default = await server._vod_guard_limits()
        with mock.patch.object(server, "db", FakeDb({"vod_min_free_gb": "0.5", "vod_max_backlog_gb": "junk",
                                                      "vod_orphan_max_age_days": "3"})):
            custom = await server._vod_guard_limits()
        return default, custom

    default, custom = asyncio.run(go())
    assert default == (1024 ** 3, 2 * 1024 ** 3, 14), default
    assert custom == (512 * 1024 ** 2, 2 * 1024 ** 3, 3), custom   # an unusable value falls back to the default


def test_settings_are_saved_validated_and_listed():
    import database

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
            d = database.Database(os.path.join(t, "p.db"))
            await d.connect()
            try:
                cfg = await d.get_retention_config()
                assert (cfg["vod_min_free_gb"], cfg["vod_max_backlog_gb"], cfg["vod_orphan_max_age_days"]) == \
                    ("1", "2", "14"), cfg
                await d.set_retention_config({"vod_min_free_gb": "0.25", "vod_max_backlog_gb": 0,
                                              "vod_orphan_max_age_days": "30"})
                cfg = await d.get_retention_config()
                assert (cfg["vod_min_free_gb"], cfg["vod_max_backlog_gb"], cfg["vod_orphan_max_age_days"]) == \
                    ("0.25", "0", "30"), cfg
                await d.set_retention_config({"vod_min_free_gb": "-1", "vod_max_backlog_gb": "abc",
                                              "vod_orphan_max_age_days": "-3"})
                cfg2 = await d.get_retention_config()
                assert cfg2 == cfg, "invalid values must be ignored"
            finally:
                await d.close()

    asyncio.run(go())


def test_alert_event_is_registered():
    import webhook_formats as wf
    assert "vod.recording_stopped" in alerts.EVENT_NAMES and "vod.recording_stopped" in wf.ALERT_EVENTS
    assert alerts.GROUP_OF["vod.recording_stopped"] == "operations"
    assert wf.event_subscribed(["*"], "vod.recording_stopped", kind="system") is False


def test_my_vods_api_carries_the_guard_state():
    src = (ROOT / "server.py").read_text()
    assert '"recording_guard": _vod_guard_public(token.user_id)' in src
    a = src.index("async def http_list_vods(")
    body = src[a:src.index("async def http_download_vod(")]
    assert body.count('"recording_guard": guard') >= 4, "the error answers must carry the guard state too"


def test_a_chatty_ffmpeg_does_not_block_on_its_stderr_pipe_and_still_hears_q():
    """Nobody used to read the recorder's stderr: with a full pipe ffmpeg blocks in write() and never
    sees "q". debug logging fills the pipe in seconds."""
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})
        env.extra_input = ["-loglevel", "debug"]

        async def go():
            with env:
                await env.start()
                rec = server.active_recordings[9]
                await asyncio.sleep(8)   # far more than the 64 KB pipe plus the reader's buffer holds
                alive = rec["process"].returncode is None
                task = rec.get("stderr_task")
                started = asyncio.get_event_loop().time()
                how = await server._vod_graceful_stop(rec["process"])
                took = asyncio.get_event_loop().time() - started
                await asyncio.sleep(0.5)
                return alive, task is not None, how, took, rec.get("stderr_tail"), rec["session_dir"]

        alive, had_task, how, took, tail, session_dir = asyncio.run(go())
        assert alive and had_task
        assert how == "q" and took < 5, (how, took)
        assert tail, "the last lines of ffmpeg's output are kept"
        check_chunks(session_dir, 1)
    assert children_of_this_process() == []


class _HungConn:
    def close(self):
        pass


class _HungSftp:
    """An SFTP session that was accepted and then stops answering (a remote whose disk hangs)."""

    def __init__(self, hang):
        self.hang = hang          # "stat": every stat waits forever; "put": put takes 8 s, then fails
        self.entered = asyncio.Event()
        self.armed = False        # the remote only starts to hang once the recording is running

    async def stat(self, path):
        if self.hang == "stat" and self.armed:
            self.entered.set()
            await asyncio.Event().wait()
        raise server.asyncssh.SFTPNoSuchFile("no")

    async def mkdir(self, path):
        pass

    async def put(self, local, remote):
        self.entered.set()
        await asyncio.sleep(8)
        raise OSError("the remote went away")

    async def remove(self, path):
        pass


def _guard_with_a_degraded_remote(hang, limit_seconds):
    with tempfile.TemporaryDirectory(prefix="vodguard_") as t:
        env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})  # guard off until raised
        sftp = _HungSftp(hang)

        async def connect(uid):
            return _HungConn(), sftp, None

        env.blocked = connect

        async def go():
            with env:
                await env.start()
                rec = server.active_recordings[9]
                process = rec["process"]
                sftp.armed = True
                assert await wait_until(sftp.entered.is_set, 20), "the upload pass never reached the remote"
                assert process.returncode is None
                env.db.settings["vod_min_free_gb"] = "1000000"
                loop = asyncio.get_event_loop()
                raised = loop.time()
                stopped = await wait_until(lambda: process.returncode is not None, limit_seconds)
                return stopped, loop.time() - raised, process.returncode, env.alerts_sent(), rec["session_dir"]

        stopped, took, rc, sent, session_dir = asyncio.run(go())
        assert stopped, f"the guard did not stop the recording within {limit_seconds} s while SFTP hung"
        assert rc == 0, rc
        assert sent == ["vod.recording_stopped"], sent
        check_chunks(session_dir, 1)
    assert children_of_this_process() == []


def test_the_guard_stops_a_recording_while_the_remote_hangs_on_stat():
    """The pass used to run before the guard in one loop: a stat that never answers starved the guard
    and ffmpeg kept filling the disk."""
    _guard_with_a_degraded_remote("stat", 6)


def test_the_guard_stops_a_recording_while_a_slow_upload_is_running():
    """A put that takes 8 s (the real one may take 300 s per chunk) must not delay the guard past a tick."""
    _guard_with_a_degraded_remote("put", 4)


def test_remote_folder_calls_give_up_when_the_remote_hangs():
    class Hung:
        async def stat(self, path):
            await asyncio.Event().wait()

        async def listdir(self, path):
            await asyncio.Event().wait()

    async def go():
        loop = asyncio.get_event_loop()
        out = []
        with mock.patch.object(server, "VOD_SFTP_META_TIMEOUT", 0.2):
            t0 = loop.time()
            try:
                await asyncio.wait_for(server._sftp_makedirs(Hung(), "/a/b"), 3)
            except asyncio.TimeoutError:
                pass
            out.append(loop.time() - t0)
        return out

    (took,) = asyncio.run(go())
    assert took < 1.5, took


def test_the_my_vods_page_shows_the_notice_and_the_admin_page_has_the_settings():
    vods = (ROOT / "static" / "js" / "vods.js").read_text()
    index = (ROOT / "static" / "index.html").read_text()
    admin = (ROOT / "static" / "admin.html").read_text()
    assert vods.count("recording_guard") >= 2 and "showVodGuardNotice" in vods
    assert "textContent = guard.message" in vods or "message.textContent = guard.message" in vods
    assert "innerHTML" not in vods[vods.index("function showVodGuardNotice"):vods.index("async function loadVods")]
    box = index[index.index('id="vods-guard-notice"'):]
    box = box[:box.index("</div>")]
    assert "onclick" not in box and 'role="status"' in box
    assert "/static/js/vods.js?v=7" in index
    for field in ("ret-vod-min-free", "ret-vod-backlog", "ret-vod-orphan-age"):
        assert f'id="{field}"' in admin, field
    for key in ("vod_min_free_gb: pFloat('ret-vod-min-free', 1)", "vod_max_backlog_gb: pFloat('ret-vod-backlog', 2)",
                "vod_orphan_max_age_days: pInt('ret-vod-orphan-age', 14)"):
        assert key in admin, key


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as e:  # noqa: BLE001
                failed += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {e!r}")
    sys.exit(1 if failed else 0)
