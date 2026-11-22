"""Smoke check: the VOD staging folder lives under the data folder, survives a restart,
is not served, is migrated from the old /tmp location, refuses to start a session
when the disk is nearly full, refuses an unsafe VOD_TEMP_DIR (falling back to the
default without touching it), keeps a custom folder through snapshot and rollback,
retries recovery from the data cleanup loop with one pass at a time, and removes
chunks that can never be delivered after 14 days.

A real ffmpeg, MediaMTX and SFTP server are not available in a stage. The recording
start and the post-restart upload therefore run in-process (ctx.run_py) with the
ffmpeg process and the SFTP connection replaced by fakes; everything else (folder
creation, modes, session record, free-space guard, migration, recovery, snapshot
exclusion, static routes) is the real code. Two separate interpreter runs stand in
for "before" and "after" a restart.
"""
import json
import os
import stat
from pathlib import Path

import aiohttp
from yarl import URL

PW = "vodtmp-owner-pass-1234"
MARK = "VODTMP-CHUNK-CONTENT-7f3a"

COMMON = r'''
import asyncio, json, os, stat, sys
from pathlib import Path
from unittest import mock
from database import db
import server, vod_staging


def mode(p):
    return "%04o" % stat.S_IMODE(os.stat(p).st_mode)


class FakeProc:
    returncode = None
    stderr = None
    async def wait(self):
        return 0
    def send_signal(self, *a):
        pass


async def fake_exec(*a, **k):
    return FakeProc()


async def noop(*a, **k):
    return None


def result(d):
    print("RESULT " + json.dumps(d))

def _limits(min_free, max_backlog=0, max_age_days=14):
    async def fixed():
        return min_free, max_backlog, max_age_days
    return fixed
'''

BEFORE = COMMON + (r'''
from auth import create_user

async def main():
    await db.connect()
    server.db = db
    uid = (await create_user("vodtmp_owner", %(pw)r))["id"]
    out = {"uid": uid, "vod_dir": server.VOD_TEMP_DIR}
    stream = {"id": 4242, "user_id": uid, "name": "Smoke Show", "owner_username": "vodtmp_owner"}

    async def storage(_uid):
        return {"remote_path": "/vods"}

    async def mtx():
        return {"api": 1}

    async def no_sftp(_uid):
        return None, None, "unreachable"

    started = []

    async def spy_exec(*a, **k):
        started.append(a)
        return FakeProc()

    with mock.patch.object(db, "get_vod_storage", storage), \
            mock.patch.object(server, "_get_mediamtx_config", mtx), \
            mock.patch.object(server, "_connect_vod_sftp", no_sftp), \
            mock.patch.object(server, "_vod_chunk_uploader", noop), \
            mock.patch.object(server.asyncio, "create_subprocess_exec", spy_exec):
        # 1. not enough free space: refused, nothing created, reason logged
        with mock.patch.object(server, "_vod_guard_limits", _limits(1 << 62)):
            await server.start_vod_recording(stream, "live_smoke")
        out["low_space_started"] = bool(started) or 4242 in server.active_recordings
        out["low_space_dirs"] = sorted(n for n in os.listdir(server.VOD_TEMP_DIR) if n != vod_staging.MARKER_NAME)
        cur = await db.conn.execute("SELECT action, detail FROM activity_log WHERE user_id = ?", (uid,))
        out["activity"] = [dict(r) for r in await cur.fetchall()]
        # 2. enough space: a session folder with a private session record
        with mock.patch.object(server, "_vod_guard_limits", _limits(1)):
            await server.start_vod_recording(stream, "live_smoke")
        rec = server.active_recordings.get(4242)
        out["started"] = bool(rec) and len(started) == 1
        if rec:
            sd = rec["session_dir"]
            out["session_dir"] = sd
            out["session_in_vod_dir"] = os.path.dirname(sd) == server.VOD_TEMP_DIR
            out["session_mode"] = mode(sd)
            out["sidecar_mode"] = mode(os.path.join(sd, vod_staging.SIDECAR_NAME))
            out["sidecar"] = vod_staging.read_sidecar(sd)
            # a chunk that has not been uploaded yet
            Path(sd, "chunk_000.mkv").write_text(%(mark)r)
    out["vod_dir_mode"] = mode(server.VOD_TEMP_DIR)
    await db.close()
    result(out)

asyncio.run(main())
''' % {"pw": PW, "mark": MARK})

# A fresh interpreter: this is what the portal does after a restart.
AFTER = COMMON + (r'''
class FakeSftp:
    def __init__(self, existing):
        import asyncssh
        self._exc = asyncssh.SFTPNoSuchFile
        self._fail = asyncssh.SFTPFailure
        self.files = {p: "remote-original" for p in existing}
        self.dirs = set()
    async def stat(self, path):
        import types
        if path in self.files:
            return types.SimpleNamespace(size=len(self.files[path]))
        if path in self.dirs:
            return types.SimpleNamespace(size=0)
        raise self._exc("no such file")
    async def listdir(self, path):
        prefix = path.rstrip("/") + "/"
        return [p[len(prefix):] for p in self.files if p.startswith(prefix) and "/" not in p[len(prefix):]]
    async def mkdir(self, path):
        self.dirs.add(path)
    async def put(self, local, remote):
        self.files[remote] = Path(local).read_text()
    async def rename(self, old, new):
        if new in self.files:
            raise self._fail("destination exists")
        self.files[new] = self.files.pop(old)
    async def remove(self, path):
        del self.files[path]


async def main():
    out = {}
    leftovers = server._vod_prepare_staging()
    out["leftovers"] = [os.path.basename(d) for d in leftovers]
    chunk = [Path(d, "chunk_000.mkv") for d in leftovers if Path(d, "chunk_000.mkv").exists()]
    out["chunk_survived"] = bool(chunk) and chunk[0].read_text() == %(mark)r
    sftp = FakeSftp(existing=["/vods/Smoke_Show/%%s/chunk_000.mkv" %% os.path.basename(leftovers[0]).split("_")[1]] if leftovers else [])

    async def fake_connect(uid):
        return mock.Mock(), sftp, None

    from config import Config
    out["stage_mode"] = bool(Config.STAGE_MODE)
    with mock.patch.object(server, "_connect_vod_sftp", fake_connect):
        # a staged instance only reports: nothing is uploaded or removed (the storage is no loopback test server)
        await server.recover_vod_staging(leftovers)
        out["stage_pass_remote"] = {k: v for k, v in sftp.files.items()}
        out["stage_pass_chunk_kept"] = bool(chunk) and chunk[0].exists()
        # the same pass as a real portal runs it; the fake store stands in for the remote
        with mock.patch.object(Config, "STAGE_MODE", False):
            await server.recover_vod_staging(leftovers)
    out["remote"] = {k: v for k, v in sftp.files.items()}
    out["leftover_dirs_after"] = sorted(n for n in os.listdir(server.VOD_TEMP_DIR) if n != vod_staging.MARKER_NAME)
    result(out)

asyncio.run(main())
''' % {"mark": MARK})

MIGRATE = COMMON + r'''
import errno, shutil, tempfile

base = tempfile.mkdtemp(prefix="vodmig_", dir=os.getcwd())
legacy = os.path.join(base, "legacy")
new = os.path.join(base, "new")
os.mkdir(legacy)
os.mkdir(new)
outside = os.path.join(base, "outside.txt")
Path(outside).write_text("outside")

def session(root, name, body):
    d = Path(root, name)
    d.mkdir()
    (d / "chunk_000.mkv").write_text(body)
    return d

session(legacy, "10_2026-01-01_1", "moved-by-rename")
session(legacy, "11_2026-01-01_2", "moved-by-copy")
session(legacy, "12_2026-01-01_3", "collides")
session(new, "12_2026-01-01_3", "kept")
os.symlink(outside, os.path.join(legacy, "13_link"))
(Path(legacy, "11_2026-01-01_2") / "evil.mkv").symlink_to(outside)

real_rename = os.rename
def rename(src, dst, *a, **k):
    if os.path.basename(src).startswith("11_"):
        raise OSError(errno.EXDEV, "cross-device")
    return real_rename(src, dst, *a, **k)

with mock.patch("vod_staging.os.rename", rename):
    res = vod_staging.migrate_legacy(new, legacy)
out = {
    "moved": sorted(res["moved"]),
    "skipped": sorted(n for n, _ in res["skipped"]),
    "rename_body": Path(new, "10_2026-01-01_1", "chunk_000.mkv").read_text(),
    "copy_body": Path(new, "11_2026-01-01_2", "chunk_000.mkv").read_text(),
    "copy_symlink_copied": Path(new, "11_2026-01-01_2", "evil.mkv").exists() or os.path.islink(os.path.join(new, "11_2026-01-01_2", "evil.mkv")),
    "collision_kept": Path(new, "12_2026-01-01_3", "chunk_000.mkv").read_text(),
    "collision_source_left": Path(legacy, "12_2026-01-01_3", "chunk_000.mkv").exists(),
    "link_not_moved": not os.path.lexists(os.path.join(new, "13_link")),
    "outside_intact": Path(outside).read_text(),
    "new_session_mode": mode(Path(new, "10_2026-01-01_1")),
    "stage_skips_host_tmp": None,
}
# On a staged instance the real server start never touches the host /tmp.
with mock.patch("vod_staging.migrate_legacy", side_effect=AssertionError("touched host /tmp")):
    try:
        server._vod_prepare_staging()
        out["stage_skips_host_tmp"] = True
    except AssertionError:
        out["stage_skips_host_tmp"] = False
shutil.rmtree(base, ignore_errors=True)
result(out)
'''

SNAP = COMMON + r'''
import update_manager as um

async def _no_cmd(*a, **k):
    return 0, "", ""

async def _version():
    return "0.0-smoke"

um._run_cmd = _no_cmd
um._get_portal_version = _version
vod = Path(server.VOD_TEMP_DIR)
sd = vod / "snapcheck_session"
sd.mkdir(exist_ok=True)
(sd / "chunk_000.mkv").write_text("pending")
meta = asyncio.run(um.create_snapshot("smoke-vodtmp"))
snap = Path(meta["path"])
out = {
    "snapshot_has_vod_tmp": (snap / "data" / "vod_tmp").exists(),
    "rollback_preserves_data": "data" in um._ROLLBACK_PRESERVE_DIRS,
    "chunk_still_there": (sd / "chunk_000.mkv").exists(),
}
import shutil
shutil.rmtree(sd, ignore_errors=True)
shutil.rmtree(snap, ignore_errors=True)
try:
    (um.SNAPSHOTS_DIR / (meta["id"] + ".json")).unlink()
except OSError:
    pass
result(out)
'''

LOGCAP = r'''
import logging

class Cap:
    def __enter__(self):
        self.records = []
        outer = self
        class H(logging.Handler):
            def emit(self, record):
                outer.records.append(record.getMessage())
        self.h = H(level=logging.DEBUG)
        self.log = logging.getLogger("portal")
        self.old = self.log.level
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(self.h)
        return self
    def __exit__(self, *a):
        self.log.removeHandler(self.h)
        self.log.setLevel(self.old)
    def text(self):
        return "\n".join(self.records)
'''

# Unsafe VOD_TEMP_DIR values are refused at start; the refused folder is not touched.
DANGER = COMMON + LOGCAP + r'''
import tempfile, shutil

base = tempfile.mkdtemp(prefix="vodbad_", dir=os.getcwd())
# The stage directory is below /tmp, which a custom folder may not be: first
# prove that rule, then switch it off so the cases below test their own rules.
below_tmp = os.path.join(base, "below_tmp")
bad = os.path.join(base, "shared")
os.makedirs(os.path.join(bad, "empty_sub"))
Path(bad, "notes.txt").write_text("mine")
os.chmod(bad, 0o755)
default = server.Config.VOD_TEMP_DIR_DEFAULT
out = {"default": default, "cases": {}}

def attempt(path):
    server.VOD_TEMP_DIR = path
    server.Config.VOD_TEMP_DIR = path
    with Cap() as cap:
        server._vod_prepare_staging()
    return {"chosen": server.VOD_TEMP_DIR, "config": server.Config.VOD_TEMP_DIR, "log": cap.text()}

out["below_tmp"] = attempt(below_tmp)
out["below_tmp"]["created"] = os.path.exists(below_tmp)
vod_staging.TEMP_ROOTS = ()

# An empty home folder of its own: only the home rule can refuse it (an empty
# folder would otherwise be adopted), and no real home folder is involved.
fake_home = os.path.join(base, "home")
os.mkdir(fake_home)
os.environ["HOME"] = fake_home
cases = {
    "non-empty folder the portal did not create": bad,
    "project folder": os.getcwd(),
    "/tmp": "/tmp",
    "/var/tmp": "/var/tmp",
    "filesystem root": "/",
    "home directory": fake_home,
}
for label, path in cases.items():
    out["cases"][label] = attempt(path)
    out["cases"][label]["path"] = path
out["bad_mode"] = mode(bad)
out["bad_listing"] = sorted(os.listdir(bad))
out["bad_marker"] = os.path.exists(os.path.join(bad, vod_staging.MARKER_NAME))
out["tmp_marker"] = os.path.exists(os.path.join("/tmp", vod_staging.MARKER_NAME))
out["home_marker"] = os.path.exists(os.path.join(fake_home, vod_staging.MARKER_NAME))
out["home_listing"] = sorted(os.listdir(fake_home))
out["root_marker"] = os.path.exists(os.path.join(os.getcwd(), vod_staging.MARKER_NAME))
out["default_marked"] = vod_staging.has_marker(default)
good = os.path.join(base, "good")
out["good"] = attempt(good)
out["good"]["marked"] = vod_staging.has_marker(good)
out["good"]["mode"] = mode(good)
empty = os.path.join(base, "empty_adopt")
os.mkdir(empty)
os.chmod(empty, 0o755)
out["empty"] = attempt(empty)
out["empty"]["marked"] = vod_staging.has_marker(empty)
out["empty"]["mode"] = mode(empty)
shutil.rmtree(base, ignore_errors=True)
result(out)
'''

# A custom staging folder inside the project folder survives a rollback.
ROLLBACK = COMMON + r'''
import tempfile, shutil
import update_manager as um
from config import Config

vod_staging.TEMP_ROOTS = ()  # the stage directory is below /tmp; this check is about rollback, not that rule
base = Path(tempfile.mkdtemp(prefix="vodroll_", dir=os.getcwd()))
root = base / "proj"
root.mkdir()
(root / "server.py").write_text("v1\n")
(root / "requirements.txt").write_text("")
(root / "data").mkdir()
(root / "code").mkdir()
(root / "code" / "mod.py").write_text("v1\n")
direct = root / "elsewhere"
direct.mkdir()
(direct / "chunk_001.mkv").write_text("pending-direct")
nested = root / "code" / "vods"
nested.mkdir()
(nested / "chunk_002.mkv").write_text("pending-nested")
refused = root / "tools"
refused.mkdir()
(refused / "t.py").write_text("v1\n")
vod_staging.ensure_private_dir(str(direct), adopt_nonempty=True)
vod_staging.ensure_private_dir(str(nested), adopt_nonempty=True)

saved = {n: getattr(um, n) for n in ("PORTAL_DIR", "BACKUPS_DIR", "SNAPSHOTS_DIR", "HISTORY_FILE", "_run_cmd", "_get_portal_version")}
um.PORTAL_DIR = root
um.BACKUPS_DIR = root / "backups"
um.SNAPSHOTS_DIR = um.BACKUPS_DIR / "snapshots"
um.HISTORY_FILE = um.BACKUPS_DIR / "update_history.jsonl"

async def fake_run(cmd, *a, **k):
    return 0, "", ""

async def fake_version():
    return "0.0-smoke"

um._run_cmd = fake_run
um._get_portal_version = fake_version
out = {}

async def cycle(path, mutate):
    Config.VOD_TEMP_DIR = str(path)
    meta = await um.create_snapshot("smoke", db_path=str(root / "none.db"))
    mutate()
    await um._apply_rollback({"id": "j", "log": []}, meta["id"])
    await asyncio.sleep(2.2)
    return Path(meta["path"])

def mutate():
    (root / "server.py").write_text("v2\n")
    (root / "code" / "mod.py").write_text("v2\n")
    (refused / "t.py").write_text("v2\n")

async def main():
    snap = await cycle(direct, mutate)
    out["direct_not_in_snapshot"] = not (snap / "elsewhere").exists()
    out["direct_kept"] = (direct / "chunk_001.mkv").read_text() == "pending-direct"
    out["code_restored"] = (root / "server.py").read_text() == "v1\n"
    snap = await cycle(nested, mutate)
    out["nested_not_in_snapshot"] = not (snap / "code" / "vods").exists()
    out["nested_kept"] = (nested / "chunk_002.mkv").read_text() == "pending-nested"
    out["nested_sibling_restored"] = (root / "code" / "mod.py").read_text() == "v1\n"
    # a folder the portal did not create (no marker) is not frozen by a rollback
    await cycle(refused, mutate)
    out["unmarked_restored"] = (refused / "t.py").read_text() == "v1\n"

try:
    asyncio.run(main())
finally:
    for n, v in saved.items():
        setattr(um, n, v)
    shutil.rmtree(base, ignore_errors=True)
result(out)
'''

# Stale chunks, one recovery pass at a time, and the retry from the data cleanup loop.
RECOVERY = COMMON + LOGCAP + r'''
import tempfile, shutil, time
from auth import create_user

AGE = %(age)d

def session(root, name, user_id=None, chunks=(("chunk_000.mkv", "aaaa"),), days=0):
    d = Path(root, name)
    d.mkdir()
    for fn, body in chunks:
        (d / fn).write_text(body)
    if user_id is not None:
        vod_staging.write_sidecar(str(d), {"stream_id": 1, "user_id": user_id, "stream_name": "s", "remote_session_dir": "/vods/x/" + name})
    t = time.time() - days * 86400
    for n in os.listdir(d):
        os.utime(d / n, (t, t))
    return d

async def main():
    from config import Config
    await db.connect()
    server.db = db
    a = (await create_user("vodtmp_stale_a", %(pw)r))["id"]
    b = (await create_user("vodtmp_stale_b", %(pw)r))["id"]
    gone_user = 987654321
    deleted_user = (await create_user("vodtmp_stale_deleted", %(pw)r))["id"]
    await db.delete_user(deleted_user)  # the portal's own account deletion
    real_storage = db.get_vod_storage

    async def storage(uid):
        if uid == b:
            return {"remote_path": "/vods"}
        return await real_storage(uid)

    base = tempfile.mkdtemp(prefix="vodstale_", dir=os.getcwd())
    out = {}
    d_nosc_old = session(base, "1_nosc_old", None, (("chunk_000.mkv", "aaaa"), ("chunk_001.mkv", "bbbbbb")), days=15)
    d_nosc_new = session(base, "2_nosc_new", None, days=13)
    d_user = session(base, "3_user_gone", gone_user, days=0)
    d_stor = session(base, "4_storage_gone", a, days=0)
    d_down = session(base, "5_sftp_down", b, days=30)
    d_deleted = session(base, "8_deleted_account", deleted_user, days=0)
    # the same three, past the grace period: only these are removed
    d_user_old = session(base, "9_user_gone_old", gone_user, days=15)
    d_stor_old = session(base, "10_storage_gone_old", a, days=15)
    d_deleted_old = session(base, "11_deleted_account_old", deleted_user, days=15)

    connects = []

    async def down(uid):
        connects.append(uid)
        return None, None, "connection refused"

    # these folders and stores are fakes; the stage-mode gate of the sweep is checked in the restart step
    async def limits():
        return 0, 0, 14   # the grace period of the default, whatever a copied database holds

    with mock.patch.object(db, "get_vod_storage", storage), mock.patch.object(Config, "STAGE_MODE", False), \
            mock.patch.object(server, "_vod_guard_limits", limits), \
            mock.patch.object(server, "_connect_vod_sftp", down), Cap() as cap:
        await server.recover_vod_staging(vod_staging.list_session_dirs(base))
    log = cap.text()
    out["log"] = log
    out["nosc_old_removed"] = not d_nosc_old.exists()
    out["nosc_new_kept"] = (d_nosc_new / "chunk_000.mkv").exists()
    out["user_gone_kept"] = d_user.exists() and d_stor.exists() and d_deleted.exists()
    out["user_gone_removed"] = not d_user_old.exists()
    out["storage_gone_removed"] = not d_stor_old.exists()
    out["deleted_account_removed"] = not d_deleted_old.exists()
    # the owner who still exists is told once; a removed account has nobody to tell
    cur = await db.conn.execute("SELECT action, detail FROM activity_log WHERE user_id = ?", (a,))
    out["discarded_rows"] = [dict(r) for r in await cur.fetchall() if r["action"] == "vod_discarded"]
    cur = await db.conn.execute("SELECT action FROM activity_log WHERE user_id = ?", (deleted_user,))
    out["deleted_owner_rows"] = len([r for r in await cur.fetchall() if r["action"] == "vod_discarded"])
    out["sftp_down_kept"] = (d_down / "chunk_000.mkv").exists() and vod_staging.read_sidecar(str(d_down)) is not None
    out["connects"] = connects

    # one pass at a time: a second call while the first waits on the SFTP side does nothing
    for n in os.listdir(base):
        shutil.rmtree(os.path.join(base, n))
    session(base, "6_a", b)
    session(base, "7_b", b)
    gate = asyncio.Event()
    entered = asyncio.Event()
    calls = []

    async def blocked(uid):
        calls.append(uid)
        entered.set()
        await gate.wait()
        return None, None, "connection refused"

    with mock.patch.object(db, "get_vod_storage", storage), mock.patch.object(Config, "STAGE_MODE", False), \
            mock.patch.object(server, "_connect_vod_sftp", blocked):
        first = asyncio.create_task(server.recover_vod_staging(vod_staging.list_session_dirs(base)))
        await entered.wait()
        await server.recover_vod_staging(vod_staging.list_session_dirs(base))
        out["connects_while_running"] = len(calls)
        gate.set()
        await first
    out["running_flag_after"] = server._vod_recovery_running

    # the data cleanup loop starts a recovery pass
    started = []

    async def spy(session_dirs=None):
        started.append(session_dirs)

    real_sleep = asyncio.sleep
    sleeps = []

    async def fake_sleep(delay, *a, **k):
        if delay >= 3600:
            sleeps.append(delay)
            if len(sleeps) > 1:
                raise asyncio.CancelledError()
            return
        await real_sleep(delay, *a, **k)

    async def retention():
        return {"cleanup_interval_hours": 1}

    srv = server.PortalServer()
    with mock.patch.object(server, "recover_vod_staging", spy), \
            mock.patch.object(db, "get_retention_config", retention), \
            mock.patch.object(server.asyncio, "sleep", fake_sleep):
        await srv._data_cleanup_task()
        task = srv._vod_recovery_task
        if task is not None:
            await task
    out["loop_started_recovery"] = len(started) == 1 and task is not None
    shutil.rmtree(base, ignore_errors=True)
    await db.close()
    result(out)

asyncio.run(main())
''' % {"pw": PW, "age": 14}


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("no RESULT line in: " + out[-600:])


async def _raw_get(ctx, sess, raw_path):
    """GET without the client normalising dot segments or re-encoding the path."""
    url = URL(ctx.base_url + raw_path, encoded=True)
    async with sess.get(url, allow_redirects=False) as r:
        return r.status, await r.read()


async def run(ctx):
    vod_dir = Path(ctx.stage_dir) / "data" / "vod_tmp"

    # The staged server created the folder itself when it started.
    present = vod_dir.is_dir() and not vod_dir.is_symlink()
    ctx.ok("vodtmp: the server created data/vod_tmp under the project folder on start", present, str(vod_dir.relative_to(ctx.stage_dir)) if present else "missing")
    if present:
        m = stat.S_IMODE(os.stat(vod_dir).st_mode)
        ctx.ok("vodtmp: the staging folder is mode 0700", m == 0o700, f"mode={m:04o}")
    else:
        ctx.ok("vodtmp: the staging folder is mode 0700", False, "folder missing")

    # Recording start (before a restart).
    rc, out = await ctx.run_py(BEFORE)
    try:
        b = _result(out)
    except RuntimeError as e:
        ctx.ok("vodtmp: recording start ran", False, str(e))
        b = None
    if b is not None:
        ctx.ok("vodtmp: the configured staging folder is the data folder, not /tmp",
               b["vod_dir"] == str(vod_dir) and b["vod_dir"] != "/tmp/portal_vods", b["vod_dir"].replace(str(ctx.stage_dir), "<stage>"))
        ctx.ok("vodtmp: below 1 GB free no session starts (no folder, no ffmpeg)",
               b["low_space_started"] is False and b["low_space_dirs"] == [], f"dirs={b['low_space_dirs']}")
        ctx.ok("vodtmp: the refusal is written to the stream owner's activity log",
               any(a["action"] == "vod_skipped" and "free" in (a["detail"] or "") for a in b["activity"]), str(b["activity"])[:200])
        ctx.ok("vodtmp: with room, a session folder is created in the staging folder",
               b.get("started") is True and b.get("session_in_vod_dir") is True)
        ctx.ok("vodtmp: session folder is 0700 and its session record is 0600",
               b.get("session_mode") == "0700" and b.get("sidecar_mode") == "0600",
               f"dir={b.get('session_mode')} record={b.get('sidecar_mode')}")
        ctx.ok("vodtmp: the session record names the owner and the remote folder",
               (b.get("sidecar") or {}).get("user_id") == b["uid"] and (b.get("sidecar") or {}).get("remote_session_dir", "").startswith("/vods/Smoke_Show/"))
        ctx.ok("vodtmp: the staging folder stays 0700 after use", b["vod_dir_mode"] == "0700")

        # The chunk is on disk; the portal process that wrote it has exited.
        sess_dir = Path(b["session_dir"]) if b.get("session_dir") else None
        ctx.ok("vodtmp: the pending chunk is on disk once the portal process is gone",
               bool(sess_dir) and (sess_dir / "chunk_000.mkv").read_text() == MARK)

        # Not served: the planted chunk bytes must not come back from any route.
        async with ctx.http() as sess:
            name = sess_dir.name if sess_dir else "x"
            paths = [
                f"/static/../data/vod_tmp/{name}/chunk_000.mkv",
                f"/static/%2e%2e/data/vod_tmp/{name}/chunk_000.mkv",
                f"/static/..%2fdata%2fvod_tmp%2f{name}%2fchunk_000.mkv",
                f"/static/%2e%2e%2fdata%2fvod_tmp%2f{name}%2fchunk_000.mkv",
                f"/data/vod_tmp/{name}/chunk_000.mkv",
                f"/data/vod_tmp/{name}/session.json",
                f"/vod_tmp/{name}/chunk_000.mkv",
            ]
            leaks = []
            for p in paths:
                try:
                    status, body = await _raw_get(ctx, sess, p)
                except aiohttp.ClientError as e:
                    continue  # a refused request leaks nothing
                if MARK.encode() in body or b"remote_session_dir" in body:
                    leaks.append((p, status))
            ctx.ok("vodtmp: no route serves the staging folder (plain, dot-segment and encoded paths)", not leaks, str(leaks))

        # After a restart: fresh interpreter, chunk survives and uploads without overwriting.
        rc, out = await ctx.run_py(AFTER)
        try:
            a = _result(out)
        except RuntimeError as e:
            ctx.ok("vodtmp: restart recovery ran", False, str(e))
            a = None
        if a is not None:
            ctx.ok("vodtmp: after a restart the chunk is still on disk and found", a["chunk_survived"] is True, str(a["leftovers"]))
            remote = a["remote"]
            uploaded = [v for k, v in remote.items() if v == MARK]
            ctx.ok("vodtmp: the leftover chunk uploads after the restart", len(uploaded) == 1, str(sorted(remote))[:200])
            ctx.ok("vodtmp: an upload never overwrites a chunk already on the remote side",
                   sorted(v for v in remote.values() if v == "remote-original") == ["remote-original"] and
                   any(k.endswith("chunk_001.mkv") and v == MARK for k, v in remote.items()), str(sorted(remote))[:200])
            if a.get("stage_mode"):
                ctx.ok("vodtmp: in stage mode the sweep only reports, it neither uploads nor removes",
                       a["stage_pass_chunk_kept"] is True and "remote-original" in a["stage_pass_remote"].values()
                       and MARK not in a["stage_pass_remote"].values(), str(a["stage_pass_remote"])[:200])
            ctx.ok("vodtmp: the session folder is removed once everything is uploaded", a["leftover_dirs_after"] == [], str(a["leftover_dirs_after"]))

    # Migration from the old /tmp location.
    rc, out = await ctx.run_py(MIGRATE)
    try:
        m = _result(out)
    except RuntimeError as e:
        ctx.ok("vodtmp: migration ran", False, str(e))
        m = None
    if m is not None:
        ctx.ok("vodtmp: migration moves a session by rename", m["rename_body"] == "moved-by-rename" and "10_2026-01-01_1" in m["moved"])
        ctx.ok("vodtmp: migration copes with a different filesystem (copy, then delete)",
               m["copy_body"] == "moved-by-copy" and "11_2026-01-01_2" in m["moved"])
        ctx.ok("vodtmp: migration never overwrites an existing session",
               m["collision_kept"] == "kept" and m["collision_source_left"] is True and "12_2026-01-01_3" in m["skipped"])
        ctx.ok("vodtmp: migration never follows or copies a symlink",
               m["link_not_moved"] is True and m["copy_symlink_copied"] is False and m["outside_intact"] == "outside" and "13_link" in m["skipped"])
        ctx.ok("vodtmp: migrated session folders are 0700", m["new_session_mode"] == "0700")
        ctx.ok("vodtmp: a staged instance does not touch the host's /tmp", m["stage_skips_host_tmp"] is True)

    # Update snapshot and rollback.
    rc, out = await ctx.run_py(SNAP)
    try:
        s = _result(out)
    except RuntimeError as e:
        ctx.ok("vodtmp: snapshot check ran", False, str(e))
        s = None
    if s is not None:
        ctx.ok("vodtmp: an update snapshot does not copy the staging folder", s["snapshot_has_vod_tmp"] is False)
        ctx.ok("vodtmp: rollback leaves data/ (and so the staging folder) alone",
               s["rollback_preserves_data"] is True and s["chunk_still_there"] is True)


    # Unsafe VOD_TEMP_DIR values.
    rc, out = await ctx.run_py(DANGER)
    try:
        d = _result(out)
    except RuntimeError as e:
        ctx.ok("vodtmp: unsafe VOD_TEMP_DIR check ran", False, str(e))
        d = None
    if d is not None:
        reasons = {
            "non-empty folder the portal did not create": "was not created by the portal",
            "project folder": "it is the portal's project folder",
            "/tmp": "it is a shared temporary folder",
            "/var/tmp": "it is a shared temporary folder",
            "filesystem root": "it is the filesystem root",
            "home directory": "it is a home directory",
        }
        for label, c in d["cases"].items():
            ok = (c["chosen"] == d["default"] and c["config"] == d["default"] and "refused" in c["log"]
                  and "using the default" in c["log"] and reasons[label] in c["log"])
            ctx.ok(f"vodtmp: VOD_TEMP_DIR set to the {label} is refused for the right reason and the default is used",
                   ok, f"chosen={c['chosen'].replace(str(ctx.stage_dir), '<stage>')} wanted={reasons[label]!r}")
        bt = d["below_tmp"]
        ctx.ok("vodtmp: a VOD_TEMP_DIR below /tmp is refused, the default is used and nothing is created",
               bt["chosen"] == d["default"] and bt["config"] == d["default"] and "refused" in bt["log"]
               and "PrivateTmp" in bt["log"] and bt["created"] is False, bt["log"][:200])
        ctx.ok("vodtmp: a refused folder is never changed (mode, contents and marker untouched)",
               d["bad_mode"] == "0755" and d["bad_listing"] == ["empty_sub", "notes.txt"] and not d["bad_marker"]
               and not d["tmp_marker"] and not d["home_marker"] and d["home_listing"] == [] and not d["root_marker"],
               f"mode={d['bad_mode']} listing={d['bad_listing']}")
        ctx.ok("vodtmp: the default folder is marked as the portal's own", d["default_marked"] is True)
        ctx.ok("vodtmp: a new custom folder is used, created 0700 and marked",
               d["good"]["chosen"].endswith("/good") and d["good"]["marked"] and d["good"]["mode"] == "0700" and "refused" not in d["good"]["log"])
        ctx.ok("vodtmp: an empty existing folder is adopted, tightened to 0700 and marked",
               d["empty"]["chosen"].endswith("/empty_adopt") and d["empty"]["marked"] and d["empty"]["mode"] == "0700")

    # A custom folder inside the project survives a rollback.
    rc, out = await ctx.run_py(ROLLBACK)
    try:
        r = _result(out)
    except RuntimeError as e:
        ctx.ok("vodtmp: custom folder rollback check ran", False, str(e))
        r = None
    if r is not None:
        ctx.ok("vodtmp: a custom folder next to data/ is left out of the snapshot and survives a rollback",
               r["direct_not_in_snapshot"] and r["direct_kept"] and r["code_restored"], str(r))
        ctx.ok("vodtmp: a custom folder nested in a code folder survives a rollback while its neighbours are restored",
               r["nested_not_in_snapshot"] and r["nested_kept"] and r["nested_sibling_restored"], str(r))
        ctx.ok("vodtmp: a configured folder the portal did not create is not frozen by a rollback", r["unmarked_restored"], str(r))

    # Stale chunks, single recovery pass and the retry loop.
    rc, out = await ctx.run_py(RECOVERY)
    try:
        v = _result(out)
    except RuntimeError as e:
        ctx.ok("vodtmp: recovery retry check ran", False, str(e))
        v = None
    if v is not None:
        ctx.ok("vodtmp: chunks with no session record are kept at 13 days and removed at 15 days",
               v["nosc_new_kept"] and v["nosc_old_removed"], "")
        ctx.ok("vodtmp: chunks whose owner or storage is gone are kept while younger than 14 days",
               v["user_gone_kept"], "")
        ctx.ok("vodtmp: chunks whose owner or storage is gone are removed after 14 days",
               v["user_gone_removed"] and v["storage_gone_removed"], "")
        ctx.ok("vodtmp: chunks of an account deleted through the portal are removed after 14 days",
               v["deleted_account_removed"], "")
        ctx.ok("vodtmp: an owner who still exists gets one activity row for the removed folder, a deleted account none",
               len(v["discarded_rows"]) == 1 and "4 bytes" in v["discarded_rows"][0]["detail"]
               and v["deleted_owner_rows"] == 0, str(v["discarded_rows"]))
        ctx.ok("vodtmp: the removal log line names the number of chunks and bytes",
               "2 chunk(s), 10 bytes" in v["log"] and "1 chunk(s), 4 bytes" in v["log"], v["log"][-300:])
        ctx.ok("vodtmp: chunks of an owner whose storage exists but is unreachable are never removed",
               v["sftp_down_kept"] and len(v["connects"]) == 1, str(v["connects"]))
        ctx.ok("vodtmp: a second recovery pass started during a running one does nothing",
               v["connects_while_running"] == 1 and v["running_flag_after"] is False, str(v["connects_while_running"]))
        ctx.ok("vodtmp: the data cleanup loop starts a recovery pass", v["loop_started_recovery"] is True)

    ctx.skip("vodtmp: a real restart of the staged server with a real SFTP upload",
             "no ffmpeg, MediaMTX or SFTP server in a stage; the restart is two interpreter runs and the SFTP side is a fake")
