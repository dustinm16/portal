"""Boot sweep of the VOD staging folder: orphan chunks are delivered over the pinned SFTP path
the recorder uses, without ever replacing a remote chunk, and local files go only after the
remote size was checked. Runs against a real asyncssh SFTP server on loopback (its remote
tree is a temporary directory) and a real ffmpeg for the end-to-end case.

The numbering rule under test: each local chunk is delivered under a NEW number, one above the
highest chunk_NNN* name in the remote folder (".part" files and "_recovered" copies count, gaps
are not filled). A remote chunk with the same name is never replaced, never skipped, whatever
its size; the local chunk is delivered next to it.

Run: venv/bin/python tests/test_vod_sweep.py
Writes well under a megabyte, inside temporary directories; leaves no process behind.
"""
import asyncio
import logging
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import asyncssh  # noqa: E402
import outbound_guard  # noqa: E402
import vod_staging as vs  # noqa: E402

outbound_guard.install()
vs.TEMP_ROOTS = ()

import server  # noqa: E402
from config import Config  # noqa: E402

from test_vod_guard import Env, FakeDb, wait_until  # noqa: E402
from test_vod_guard_stop import check_chunks, children_of_this_process  # noqa: E402

PW = "pw-for-the-test"
REMOTE = "/v/s/2026-01-01"


class _Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == PW


class Remote:
    """A real SFTP server on loopback serving a temporary directory as its root."""

    def __init__(self, base):
        self.root = os.path.join(base, "remote")
        os.makedirs(self.root)
        self.server = None
        self.port = None

    async def __aenter__(self):
        key = asyncssh.generate_private_key("ssh-ed25519")
        root = self.root
        self.server = await asyncssh.create_server(
            _Srv, "127.0.0.1", 0, server_host_keys=[key],
            sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *a):
        self.server.close()
        await self.server.wait_closed()

    def path(self, remote):
        return os.path.join(self.root, remote.lstrip("/"))

    def put(self, remote_file, data):
        p = self.path(remote_file)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        Path(p).write_bytes(data)

    def listing(self, remote_dir):
        p = self.path(remote_dir)
        return sorted(os.listdir(p)) if os.path.isdir(p) else []

    def read(self, remote_file):
        return Path(self.path(remote_file)).read_bytes()


class SweepDb(FakeDb):
    def __init__(self, remote, settings=None, host="127.0.0.1", **kw):
        super().__init__(settings)
        self.remote, self.host = remote, host
        self.missing_storage = kw.get("missing_storage", False)
        self.missing_user = kw.get("missing_user", False)

    async def get_user_by_id(self, uid):
        return None if self.missing_user else {"id": uid, "username": "o"}

    async def get_vod_storage(self, uid):
        if self.missing_storage:
            return None
        return {"host": self.host, "port": self.remote.port, "username": "u", "auth_method": "password",
                "remote_path": "/v", "config": {"password": PW, "host_key_ignore": True}}


class Logs:
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


def stage_dir(base):
    stage = os.path.join(base, "stage")
    vs.ensure_private_dir(stage)
    return stage


def session(base, name, chunks, remote=REMOTE, user=7):
    stage_dir(base)
    d = Path(base) / "stage" / name
    d.mkdir(parents=True)
    for fname, data in chunks.items():
        (d / fname).write_bytes(data)
    vs.write_sidecar(str(d), {"stream_id": 1, "user_id": user, "stream_name": "s", "remote_session_dir": remote})
    return d


class Patched:
    """The server module wired to the real loopback SFTP server."""

    def __init__(self, base, remote, db):
        self.base, self.remote, self.db = base, remote, db

    async def _resolve(self, host, port):
        return ["127.0.0.1"]

    def __enter__(self):
        stage = os.path.join(self.base, "stage")
        os.makedirs(stage, exist_ok=True)
        vs.ensure_private_dir(stage)
        self.patches = [
            mock.patch.object(server, "VOD_TEMP_DIR", stage),
            mock.patch.object(server, "db", self.db),
            mock.patch.object(server, "resolve_checked_host", self._resolve),
            mock.patch.object(server, "_vod_staging_usable", True),
            mock.patch.object(server, "VOD_SWEEP_PAUSE", 0),
        ]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *a):
        for p in reversed(self.patches):
            p.stop()
        server._vod_sweep_claims.clear()


def run(coro):
    return asyncio.run(coro)


def test_the_test_server_refuses_to_rename_onto_an_existing_file():
    """If it did not, the no-overwrite checks below would prove nothing about a plain rename."""
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                remote.put("/a", b"one")
                remote.put("/b", b"two")
                async with asyncssh.connect("127.0.0.1", remote.port, username="u", password=PW,
                                            known_hosts=None, config=None, agent_path=None) as conn:
                    sftp = await conn.start_sftp_client()
                    try:
                        await sftp.rename("/a", "/b")
                    except asyncssh.SFTPError:
                        refused = True
                    else:
                        refused = False
                    return refused, remote.read("/b")

    refused, data = run(go())
    assert refused and data == b"two", (refused, data)


def test_delivery_never_replaces_a_remote_chunk_and_uses_new_numbers():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                # the remote day folder: chunk 0, a gap (1), chunk 2, a partial upload left by a crash
                # (same name as a local chunk, different size), and a ".part" of a later chunk
                remote.put(f"{REMOTE}/chunk_000.mkv", b"AAAAA")
                remote.put(f"{REMOTE}/chunk_002.mkv", b"CCCCCCC")
                remote.put(f"{REMOTE}/chunk_004.mkv", b"truncated")
                remote.put(f"{REMOTE}/chunk_005.mkv.part", b"half")
                before = {n: remote.read(f"{REMOTE}/{n}") for n in remote.listing(REMOTE)}
                d = session(t, "1_2026-01-01_5", {
                    "chunk_000.mkv": b"BBBBB",            # same name, same size as a remote chunk
                    "chunk_004.mkv": b"the full chunk 4",  # same name, different size
                    "chunk_007.mkv": b"seven",
                })
                with Patched(t, remote, SweepDb(remote)), Logs() as logs:
                    await server.recover_vod_staging()
                after = {n: remote.read(f"{REMOTE}/{n}") for n in remote.listing(REMOTE)}
                return before, after, d.exists(), logs.text()

    before, after, local_left, log = run(go())
    for name, data in before.items():
        assert after[name] == data, f"{name} was replaced or removed"
    new = {n: v for n, v in after.items() if n not in before}
    # highest remote number was 5 (the .part counts): the three local chunks take 6, 7 and 8, in order
    assert new == {"chunk_006.mkv": b"BBBBB", "chunk_007.mkv": b"the full chunk 4", "chunk_008.mkv": b"seven"}, new
    assert not local_left, "the folder is removed once everything was delivered"
    assert "size checked" in log


def test_local_chunk_is_removed_only_after_the_remote_size_is_checked():
    class Lying:
        """Wraps the real client; the size after the rename is reported wrong."""
        def __init__(self, inner, local_files, seen):
            self._inner, self._local, self._seen = inner, local_files, seen

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def stat(self, path):
            attrs = await self._inner.stat(path)
            if "/chunk_" in path and path.endswith(".mkv") and attrs.size:
                self._seen.append(all(os.path.exists(f) for f in self._local))  # local copy still here?
                if self.lie:
                    attrs.size = attrs.size - 1
            return attrs

        lie = False

    async def go(lie):
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                remote.put(f"{REMOTE}/chunk_000.mkv", b"old")
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"fresh data"})
                seen = []
                real_connect = server._connect_vod_sftp

                async def connect(uid):
                    conn, sftp, err = await real_connect(uid)
                    if err:
                        return conn, sftp, err
                    w = Lying(sftp, [str(d / "chunk_000.mkv")], seen)
                    w.lie = lie
                    return conn, w, None

                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "_connect_vod_sftp", connect), \
                        Logs() as logs:
                    await server.recover_vod_staging()
                return (remote.listing(REMOTE), (d / "chunk_000.mkv").exists(), seen, remote.read(f"{REMOTE}/chunk_000.mkv"),
                        logs.text())

    listing, local_exists, seen, old, log = run(go(False))
    assert listing == ["chunk_000.mkv", "chunk_001.mkv"] and not local_exists
    assert seen and all(seen), "the remote size was read while the local chunk still existed"
    assert old == b"old"
    # a wrong size after the rename: the remote copy that was just made is removed, the local chunk stays
    listing, local_exists, seen, old, log = run(go(True))
    assert listing == ["chunk_000.mkv"], listing
    assert local_exists, "a chunk whose remote size does not match must not be removed locally"
    assert old == b"old" and "instead of" in log, log


def test_a_failed_upload_keeps_the_chunk_and_leaves_no_remote_file_behind():
    class Failing:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def put(self, local, remote):
            await self._inner.put(local, remote)
            raise OSError("connection reset")

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                remote.put(f"{REMOTE}/chunk_000.mkv", b"old")
                d = session(t, "1_2026-01-01_5", {"chunk_001.mkv": b"fresh"})
                real_connect = server._connect_vod_sftp

                async def connect(uid):
                    conn, sftp, err = await real_connect(uid)
                    return conn, (Failing(sftp) if not err else sftp), err

                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "_connect_vod_sftp", connect):
                    await server.recover_vod_staging()
                return remote.listing(REMOTE), (d / "chunk_001.mkv").exists()

    listing, kept = run(go())
    assert listing == ["chunk_000.mkv"], listing
    assert kept


def test_a_folder_whose_remote_folder_a_recording_writes_to_is_skipped():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"x"})
                other = session(t, "2_other", {"chunk_000.mkv": b"y"}, remote="/v/other/2026-01-01")
                with Patched(t, remote, SweepDb(remote)):
                    live = {"session_dir": os.path.join(t, "stage", "9_live"), "remote_session_dir": REMOTE}
                    with mock.patch.dict(server.active_recordings, {9: live}):
                        await server.recover_vod_staging()
                    first = (remote.listing(REMOTE), d.exists(), remote.listing("/v/other/2026-01-01"), other.exists())
                    with mock.patch.object(server, "_vod_busy_dirs", {str(d)}):
                        await server.recover_vod_staging()
                    second = (remote.listing(REMOTE), d.exists())
                    await server.recover_vod_staging()
                    third = (remote.listing(REMOTE), d.exists())
                return first, second, third

    first, second, third = run(go())
    # a recording writes to REMOTE: that folder waits, the folder for another remote folder is delivered
    assert first == ([], True, ["chunk_000.mkv"], False), first
    assert second == ([], True), "a folder that a recording is using must not be touched"
    assert third == (["chunk_000.mkv"], False), "once nothing uses it, it is delivered"



def test_one_pass_uploads_at_most_the_cap_and_the_next_pass_continues():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                session(t, "1_a", {"chunk_000.mkv": b"a" * 100, "chunk_001.mkv": b"b" * 100,
                                   "chunk_002.mkv": b"c" * 100})
                session(t, "2_b", {"chunk_000.mkv": b"d" * 100}, remote="/v/other/2026-01-02")
                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "VOD_SWEEP_PASS_CAP_BYTES", 150):
                    await server.recover_vod_staging()
                    first = (remote.listing(REMOTE), remote.listing("/v/other/2026-01-02"),
                             vs.chunk_files(os.path.join(t, "stage", "1_a")))
                    await server.recover_vod_staging()
                    second = (remote.listing(REMOTE), remote.listing("/v/other/2026-01-02"))
                    await server.recover_vod_staging()
                    third = (remote.listing(REMOTE), remote.listing("/v/other/2026-01-02"),
                             vs.list_session_dirs(os.path.join(t, "stage")))
                return first, second, third

    first, second, third = run(go())
    # 150 bytes: two chunks of the first folder go (the cap is checked before each chunk), the rest waits
    assert first[0] == ["chunk_000.mkv", "chunk_001.mkv"] and first[1] == [] and len(first[2]) == 1, first
    # pass two has a fresh cap: the rest of the first folder (100), then the second folder
    assert second == (["chunk_000.mkv", "chunk_001.mkv", "chunk_002.mkv"], ["chunk_000.mkv"]), second
    assert third[2] == [], third


def test_stage_mode_only_reports_unless_the_target_is_loopback():
    async def go(host, stage_mode):
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_a", {"chunk_000.mkv": b"a" * 10})
                gone = session(t, "2_gone", {"chunk_000.mkv": b"g" * 10}, user=8)
                _age(str(gone), 20)
                db = SweepDb(remote, host=host)

                async def user(uid):
                    return {"id": uid}

                async def storage(uid):
                    return None if uid == 8 else await SweepDb.get_vod_storage(db, uid)

                db.get_vod_storage = storage
                with Patched(t, remote, db), mock.patch.object(Config, "STAGE_MODE", stage_mode), Logs() as logs:
                    await server.recover_vod_staging()
                return remote.listing(REMOTE), d.exists(), gone.exists(), logs.text()

    listing, kept, gone_kept, log = run(go("storage.example.org", True))
    assert listing == [] and kept and gone_kept, "stage mode against a real remote must change nothing"
    assert "would upload" in log and "would remove" in log, log
    listing, kept, gone_kept, log = run(go("127.0.0.1", True))
    assert listing == ["chunk_000.mkv"] and not kept, "a loopback target is the test server"
    assert gone_kept, "with no storage there is no loopback target: a removal is only reported in stage mode"
    listing, kept, gone_kept, log = run(go("storage.example.org", False))
    assert not kept and not gone_kept  # outside stage mode it is a real run


def _age(path, days):
    import time
    t = time.time() - days * 86400
    for n in os.listdir(path):
        os.utime(os.path.join(path, n), (t, t))


def test_removal_rules_and_every_removal_is_logged_with_name_size_and_reason():
    async def go(setup, **dbkw):
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                d = setup(t)
                settings = dbkw.pop("settings", None)
                db = SweepDb(remote, settings, **dbkw)
                go.db = db
                with Patched(t, remote, db), Logs() as logs:
                    await server.recover_vod_staging()
                return d.exists(), logs.text()

    def aged(days, name, size=1):
        def make(t):
            d = session(t, name, {"chunk_000.mkv": b"x" * size})
            _age(str(d), days)
            return d
        return make

    # owner without storage: kept for the grace period like a folder without a record, then removed
    # with name, size and reason in the log and one activity row for the owner
    exists, log = run(go(aged(5, "1_nostorage", 123), missing_storage=True))
    assert exists and go.db.activity == [], "a young folder of an owner without storage must be kept"
    assert "kept" in log and "no VOD storage" in log, log
    exists, log = run(go(aged(20, "1_nostorage", 123), missing_storage=True))
    assert not exists and "1_nostorage" in log and "123 bytes" in log and "no VOD storage" in log, log
    rows = [a for a in go.db.activity if a[1] == "vod_discarded"]
    assert len(rows) == 1 and rows[0][0] == 7 and "123 bytes" in rows[0][2] and "1_nostorage" in rows[0][2], rows
    assert "/" not in rows[0][2], "the activity row must not carry a path"
    exists, log = run(go(aged(400, "1_nostorage"), missing_storage=True, settings={"vod_orphan_max_age_days": "0"}))
    assert exists, "0 switches the age rule off for an owner without storage too"
    # owner gone: the same grace period, and no activity row (there is nobody to show it to)
    exists, log = run(go(aged(5, "1_nouser"), missing_user=True))
    assert exists, "a young folder of a removed owner must be kept"
    exists, log = run(go(aged(20, "1_nouser"), missing_user=True))
    assert not exists and "no longer exists" in log and go.db.activity == [], log
    # no session record: kept while young, removed when older than the setting (default 14 days)
    def norecord(days):
        def make(t):
            stage_dir(t)
            d = Path(t) / "stage" / "1_norecord"
            d.mkdir(parents=True)
            (d / "chunk_000.mkv").write_bytes(b"x" * 5)
            _age(str(d), days)
            return d
        return make
    exists, log = run(go(norecord(5)))
    assert exists, "a young folder without a record must be kept"
    exists, log = run(go(norecord(20)))
    assert not exists and "1_norecord" in log and "5 bytes" in log and "older than 14 days" in log, log
    exists, log = run(go(norecord(5), settings={"vod_orphan_max_age_days": "3"}))
    assert not exists and "older than 3 days" in log, log
    exists, log = run(go(norecord(400), settings={"vod_orphan_max_age_days": "0"}))
    assert exists, "0 switches the age rule off"
    # storage configured but the target blocked: never removed for age
    async def blocked():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_down", {"chunk_000.mkv": b"x"})
                _age(str(d), 400)
                db = SweepDb(remote)
                remote.port = 1   # nothing listens there
                with Patched(t, remote, db):
                    await server.recover_vod_staging()
                return (d / "chunk_000.mkv").exists()
    assert run(blocked()), "chunks of a configured, unreachable storage must be kept however old they are"


def test_numbers_taken_by_the_sweep_are_not_reused_by_a_recording_that_starts_meanwhile():
    class Sftp:
        def __init__(self):
            self.files = {}

        async def stat(self, p):
            if p in self.files:
                import types
                return types.SimpleNamespace(size=len(self.files[p]))
            raise asyncssh.SFTPNoSuchFile("x")

        async def put(self, local, remote):
            self.files[remote] = Path(local).read_bytes()

        async def rename(self, a, b):
            self.files[b] = self.files.pop(a)

        async def remove(self, p):
            self.files.pop(p, None)

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            a = Path(t) / "a"
            b = Path(t) / "b"
            a.write_bytes(b"1")
            b.write_bytes(b"2")
            sftp = Sftp()
            top = await server._vod_sweep_put(sftp, REMOTE, str(a), 1, 3)
            top2 = await server._vod_sweep_put(sftp, REMOTE, str(b), 1, 3)  # a stale listing says 3 again
            claims = dict(server._vod_sweep_claims)
            server._vod_sweep_claims.clear()
            return top, top2, sorted(sftp.files), claims

    top, top2, files, claims = run(go())
    assert (top, top2) == (4, 5) and claims == {REMOTE: 5}, (top, top2, claims)
    assert files == [f"{REMOTE}/chunk_004.mkv", f"{REMOTE}/chunk_005.mkv"], files


def test_a_recording_that_starts_during_the_sweep_numbers_above_what_the_sweep_delivered_even_if_the_pass_ends_first():
    """The recorder lists the remote folder before the sweep renames its chunk, then its thread-pool hop
    stalls until the whole pass is over: the sweep's claim must outlive the pass."""
    import threading
    from datetime import datetime, timezone

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                day = f"/v/s/{today}"
                for i in range(3):
                    remote.put(f"{day}/chunk_{i:03d}.mkv", b"old%d" % i)
                session(t, "1_orphan", {"chunk_000.mkv": b"orphan-data"}, remote=day)
                entered = threading.Event()      # the recorder reached the thread-pool hop (its listdir is done)
                release = threading.Event()
                real_connect = server._connect_vod_sftp
                sweeping = {"on": True}

                class Hook:
                    def __init__(self, inner):
                        self._i = inner

                    def __getattr__(self, name):
                        return getattr(self._i, name)

                    async def put(self, a, b):
                        while not entered.is_set():
                            await asyncio.sleep(0.01)
                        return await self._i.put(a, b)

                async def connect(uid):
                    conn, sftp, err = await real_connect(uid)
                    return conn, (Hook(sftp) if (sweeping["on"] and not err) else sftp), err

                real_nf = vs.next_free_chunk_number

                def slow_nf(*a):
                    entered.set()
                    release.wait(30)
                    return real_nf(*a)

                captured = {}

                async def fake_exec(cmd, *a, **k):
                    captured["start"] = int(cmd[cmd.index("-segment_start_number") + 1])
                    raise FileNotFoundError

                async def mtx():
                    return {"x": 1}

                with Patched(t, remote, SweepDb(remote, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})), \
                        mock.patch.object(server, "_connect_vod_sftp", connect), \
                        mock.patch.object(server, "_PROJECT_ROOT", os.path.join(t, "project")), \
                        mock.patch.object(server, "_get_mediamtx_config", mtx), \
                        mock.patch.object(server, "_media_exec", fake_exec), \
                        mock.patch.object(server.vod_staging, "next_free_chunk_number", slow_nf):
                    sweep = asyncio.create_task(server.recover_vod_staging())
                    while not sweep.done() and not server._vod_recovery_running:
                        await asyncio.sleep(0.01)
                    await asyncio.sleep(0.2)     # the sweep is at its put (waiting for the recorder)
                    sweeping["on"] = False
                    rec = asyncio.create_task(server.start_vod_recording({"id": 5, "user_id": 7, "name": "s"}, "live_x"))
                    await sweep                  # the pass is over, the recorder has not read anything yet
                    release.set()
                    await rec
                return remote.listing(day), captured.get("start")

    listing, start = run(go())
    delivered = max(int(n[6:9]) for n in listing)
    assert delivered == 3, listing                 # the sweep delivered the orphan as chunk_003
    assert start is not None and start > delivered, (start, listing)


def test_end_to_end_guard_stop_then_restart_delivers_the_chunks():
    """SFTP target blocked and a tiny backlog limit: the recording stops cleanly with one alert; after a
    'restart' (a recovery pass with the target reachable) the chunks are uploaded without replacing an
    existing remote chunk, and the local files are gone."""
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                env = Env(t, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0.00005"})
                with env:
                    await env.start()
                    rec = server.active_recordings[9]
                    session_dir, process = rec["session_dir"], rec["process"]
                    assert await wait_until(lambda: 9 not in server.active_recordings, 25), "not stopped"
                    await asyncio.sleep(1.0)
                    stopped_rc, sent = process.returncode, env.alerts_sent()
                    meta = vs.read_sidecar(session_dir)
                    chunks = check_chunks(session_dir, 2)
                    sizes = {os.path.basename(c): os.path.getsize(c) for c in chunks}
                # "restart": the remote already holds chunk_000 of that day (a different recording)
                remote_dir = meta["remote_session_dir"]
                remote.put(f"{remote_dir}/chunk_000.mkv", b"someone else's chunk")
                db = SweepDb(remote, {"vod_max_backlog_gb": "0"})
                with Patched(t, remote, db):
                    await server.recover_vod_staging()
                delivered = {n: remote.path(f"{remote_dir}/{n}") for n in remote.listing(remote_dir)}
                good = remote.read(f"{remote_dir}/chunk_000.mkv")
                for n, p in delivered.items():
                    if n != "chunk_000.mkv":
                        assert os.path.getsize(p) in sizes.values()
                        # the delivered copy plays too
                        check_chunks_file(p)
                return stopped_rc, sent, sorted(delivered), good, vs.list_session_dirs(env.stage), len(chunks)

    stopped_rc, sent, delivered, good, left, n_chunks = run(go())
    assert stopped_rc == 0 and sent == ["vod.recording_stopped"], (stopped_rc, sent)
    assert good == b"someone else's chunk", "an existing remote chunk was replaced"
    assert len(delivered) == 1 + n_chunks and "chunk_000.mkv" in delivered, delivered
    assert left == [], "local folder must be gone after delivery"
    assert children_of_this_process() == []


def check_chunks_file(path):
    import subprocess
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and not r.stderr.strip() and r.stdout.strip() not in ("", "N/A"), (path, r)


def test_a_recording_that_starts_while_the_sweep_is_delivering_stops_the_sweep_before_it_takes_another_number():
    class Hook:
        """After the first chunk reached the remote folder, a recording starts for that folder."""
        def __init__(self, inner, started):
            self._inner, self._started = inner, started

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def put(self, local, remote):
            await self._inner.put(local, remote)
            self._started()

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                remote.put(f"{REMOTE}/chunk_000.mkv", b"old")
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"aaa", "chunk_001.mkv": b"bbb", "chunk_002.mkv": b"ccc"})
                real_connect = server._connect_vod_sftp
                live = {"session_dir": os.path.join(t, "stage", "9_live"), "remote_session_dir": REMOTE}

                def start_recording():
                    server.active_recordings[9] = live

                async def connect(uid):
                    conn, sftp, err = await real_connect(uid)
                    return conn, (Hook(sftp, start_recording) if not err else sftp), err

                try:
                    with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "_connect_vod_sftp", connect):
                        await server.recover_vod_staging()
                finally:
                    server.active_recordings.pop(9, None)
                return remote.listing(REMOTE), sorted(os.path.basename(c) for c in vs.chunk_files(str(d)))

    listing, left = run(go())
    assert listing == ["chunk_000.mkv", "chunk_001.mkv"], listing   # the first chunk went (as 001), then it stopped
    assert left == ["chunk_001.mkv", "chunk_002.mkv"], left          # the others wait; nothing was removed that was not delivered


def _live_upload_after_failed_start_listing(mode: str):
    """A morning recording left chunk_000..002 in today's remote folder. A new recording starts while
    the start listing is slow (mode "slow") or the connection is refused (mode "down"), so it numbers
    from 0; then the live uploader runs once SFTP answers. Returns (start number, remote listing, files)."""
    from datetime import datetime, timezone

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodlive_") as t:
            async with Remote(t) as remote:
                today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                rdir = f"/v/s/{today}"
                for i in range(3):
                    remote.put(f"{rdir}/chunk_{i:03d}.mkv", b"MORNING-%d" % i)
                real_connect = server._connect_vod_sftp
                calls = {"n": 0}

                class Slow:
                    def __init__(self, inner):
                        self._i = inner

                    def __getattr__(self, name):
                        return getattr(self._i, name)

                    async def listdir(self, path):
                        await asyncio.sleep(2)
                        return await self._i.listdir(path)

                async def connect(uid):
                    calls["n"] += 1
                    if calls["n"] == 1:
                        if mode == "down":
                            return None, None, "connection refused"
                        conn, sftp, err = await real_connect(uid)
                        return conn, Slow(sftp), err
                    return await real_connect(uid)

                captured = {}

                async def fake_exec(cmd, *a, **k):
                    captured["start"] = int(cmd[cmd.index("-segment_start_number") + 1])
                    raise FileNotFoundError  # no ffmpeg is started

                async def mtx():
                    return {"x": 1}

                db = SweepDb(remote, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})
                with Patched(t, remote, db), \
                        mock.patch.object(server, "_connect_vod_sftp", connect), \
                        mock.patch.object(server, "VOD_SFTP_META_TIMEOUT", 0.5), \
                        mock.patch.object(server, "_get_mediamtx_config", mtx), \
                        mock.patch.object(server, "_media_exec", fake_exec):
                    await server.start_vod_recording({"id": 5, "user_id": 7, "name": "s"}, "live_x")
                    start = captured["start"]
                    sd = os.path.join(t, "stage", "5_live")
                    os.makedirs(sd)
                    Path(sd, f"chunk_{start:03d}.mkv").write_bytes(b"EVENING-new")
                    Path(sd, f"chunk_{start + 1:03d}.mkv").write_bytes(b"EVENING-growing")
                    rec = {"session_dir": sd, "remote_session_dir": rdir, "user_id": 7, "uploaded": set()}
                    await server._do_vod_chunk_upload(rec, final=False)
                files = {n: remote.read(f"{rdir}/{n}") for n in remote.listing(rdir)}
                return start, files

    return run(go())


def test_the_live_uploader_never_replaces_a_remote_chunk_when_the_start_listing_failed():
    for mode in ("slow", "down"):
        start, files = _live_upload_after_failed_start_listing(mode)
        assert start == 0, (mode, start)   # the numbering really fell back to 0
        for i in range(3):
            assert files[f"chunk_{i:03d}.mkv"] == b"MORNING-%d" % i, (mode, files)
        assert b"EVENING-new" in files.values(), (mode, files)   # delivered, next to the old ones
        assert not [n for n in files if n.endswith(".part")], (mode, files)


def _live_rec(t, name, chunks, rdir):
    sd = os.path.join(t, "stage", name)
    os.makedirs(sd)
    for fname, data in chunks.items():
        Path(sd, fname).write_bytes(data)
    return {"session_dir": sd, "remote_session_dir": rdir, "user_id": 7, "uploaded": set()}


def test_two_live_uploaders_into_one_remote_folder_lose_and_mix_no_chunk():
    """Two recordings whose names clean up to the same folder ("My Show" and "My Show!") upload into one
    remote folder at the same time. Each chunk must arrive whole under its own number, and each local
    chunk goes only then."""
    a, b = b"A" * (3 * 1024 * 1024), b"B" * (2 * 1024 * 1024)

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodlive2_") as t:
            async with Remote(t) as remote:
                rdir = "/v/s/2026-01-01"
                with Patched(t, remote, SweepDb(remote, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})):
                    ra = _live_rec(t, "a", {"chunk_001.mkv": a}, rdir)
                    rb = _live_rec(t, "b", {"chunk_001.mkv": b}, rdir)
                    await asyncio.gather(server._do_vod_chunk_upload(ra, final=True),
                                         server._do_vod_chunk_upload(rb, final=True))
                names = remote.listing(rdir)
                got = sorted(remote.read(f"{rdir}/{n}") for n in names)
                return names, got, [os.listdir(ra["session_dir"]), os.listdir(rb["session_dir"])]

    names, got, left = run(go())
    assert got == sorted([a, b]), (names, [len(x) for x in got])
    assert not [n for n in names if n.endswith(".part")], names
    assert left == [[], []], left


def test_a_chunk_the_remote_did_not_keep_in_full_stays_local_and_is_retried():
    """A remote that acknowledges a write it did not keep (a full or faulty storage) must not cost the
    only complete copy: the short remote file is removed, the local chunk stays, the next pass delivers."""
    data = b"C" * 100000

    class Short:
        def __init__(self, inner, tmp):
            self._inner, self._tmp = inner, tmp

        def __getattr__(self, name):
            return getattr(self._inner, name)

        async def put(self, local, remote, *a, **k):
            half = os.path.join(self._tmp, "half")
            Path(half).write_bytes(Path(local).read_bytes()[:len(data) // 2])
            return await self._inner.put(half, remote, *a, **k)

    async def go():
        with tempfile.TemporaryDirectory(prefix="vodlive3_") as t:
            async with Remote(t) as remote:
                rdir = "/v/s/2026-01-01"
                real_connect = server._connect_vod_sftp

                async def short_connect(uid):
                    conn, sftp, err = await real_connect(uid)
                    return conn, (Short(sftp, t) if sftp else sftp), err

                db = SweepDb(remote, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0"})
                with Patched(t, remote, db), Logs() as logs:
                    rec = _live_rec(t, "a", {"chunk_000.mkv": data}, rdir)
                    with mock.patch.object(server, "_connect_vod_sftp", short_connect):
                        await server._do_vod_chunk_upload(rec, final=True)
                    kept = os.path.exists(os.path.join(rec["session_dir"], "chunk_000.mkv"))
                    after_short = remote.listing(rdir)
                    rec["uploaded"].clear()
                    await server._do_vod_chunk_upload(rec, final=True)   # a healthy remote: the retry delivers
                return kept, after_short, remote.listing(rdir), remote.read(f"{rdir}/chunk_000.mkv"), logs.text(), \
                    os.listdir(rec["session_dir"])

    kept, after_short, final, body, log, left = run(go())
    assert kept and after_short == [], (kept, after_short)
    assert "instead of" in log
    assert final == ["chunk_000.mkv"] and body == data and left == [], (final, left)


class _Hanging:
    """Wraps an SFTP client; the n-th call of one method never answers (a remote that stops replying)."""

    def __init__(self, inner, method, nth=1):
        self._inner, self._method, self._nth, self._count = inner, method, nth, 0

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _maybe(self, name):
        if name == self._method:
            self._count += 1
            return self._count == self._nth
        return False

    async def stat(self, path):
        if self._maybe("stat"):
            await asyncio.sleep(3600)
        return await self._inner.stat(path)

    async def rename(self, a, b):
        if self._maybe("rename"):
            await asyncio.sleep(3600)
        return await self._inner.rename(a, b)


def test_every_sftp_metadata_call_of_the_sweep_has_a_time_limit_and_the_pass_ends():
    """stat after the put, rename, stat after the rename: each hangs once. The call must give up,
    the chunk stays local, nothing half-made stays on the remote, and the running flag is cleared."""
    cases = [("stat", 2, "stat after the put"), ("rename", 1, "rename"), ("stat", 3, "stat after the rename")]

    async def one(method, nth):
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"payload"})
                real_connect = server._connect_vod_sftp
                hang = {"on": True}

                async def connect(uid):
                    conn, sftp, err = await real_connect(uid)
                    return conn, (_Hanging(sftp, method, nth) if (not err and hang["on"]) else sftp), err

                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "_connect_vod_sftp", connect), \
                        mock.patch.object(server, "VOD_SFTP_META_TIMEOUT", 0.3):
                    began = asyncio.get_event_loop().time()
                    # no outer cancel: the pass has to end by itself (the guard below is only a test fence)
                    await asyncio.wait_for(server.recover_vod_staging(), 20)
                    took = asyncio.get_event_loop().time() - began
                    flag = server._vod_recovery_running
                    kept = (d / "chunk_000.mkv").exists()
                    left = [n for n in remote.listing(REMOTE) if n.endswith(".part")]
                    hang["on"] = False
                    await asyncio.wait_for(server.recover_vod_staging(), 20)   # the next pass is not blocked
                    return took, flag, kept, left, remote.listing(REMOTE), d.exists()

    for method, nth, label in cases:
        took, flag, kept, left, listing, gone_after = asyncio.run(one(method, nth))
        assert took < 10, (label, took)
        assert flag is False, label
        assert kept, f"{label}: the local chunk must stay when the remote did not answer"
        assert left == [], (label, left)
        assert gone_after is False, f"{label}: the next pass delivers the chunk"
        assert any(n.startswith("chunk_") and n.endswith(".mkv") for n in listing), (label, listing)


def test_a_failing_folder_does_not_end_the_pass_and_the_flag_is_cleared():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                session(t, "1_a", {"chunk_000.mkv": b"a"})
                d2 = session(t, "2_b", {"chunk_000.mkv": b"b"}, remote="/v/other/2026-01-01")
                real = server._vod_recover_one
                seen = []

                async def recover(session_dir, budget=None):
                    seen.append(os.path.basename(session_dir))
                    if session_dir.endswith("1_a"):
                        raise RuntimeError("boom")
                    return await real(session_dir, budget)

                with Patched(t, remote, SweepDb(remote)), mock.patch.object(server, "_vod_recover_one", recover):
                    await server.recover_vod_staging()
                return seen, server._vod_recovery_running, d2.exists()

    seen, flag, d2_exists = run(go())
    assert seen == ["1_a", "2_b"] and flag is False and not d2_exists, (seen, flag, d2_exists)


def test_a_refused_start_is_followed_by_an_extra_sweep_pass_that_clears_the_backlog_once_the_remote_is_back():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodsweep_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"x" * 20000})
                db = SweepDb(remote, {"vod_min_free_gb": "0", "vod_max_backlog_gb": "0.00001"})  # about 10 KB

                async def mtx():
                    return {"x": 1}

                with Patched(t, remote, db), mock.patch.object(server, "_get_mediamtx_config", mtx), \
                        mock.patch.object(server, "_PROJECT_ROOT", os.path.join(t, "project")), \
                        mock.patch.object(server, "VOD_SWEEP_EXTRA_DELAY", 0.1):
                    server._vod_extra_sweep_at = None
                    server._vod_guard_state.clear()
                    server._vod_skip_logged.clear()
                    await server.start_vod_recording({"id": 9, "user_id": 7, "name": "S"}, "live_x")
                    refused = server._vod_guard_public(7)
                    ok = await wait_until(lambda: not d.exists(), 15)
                    task = server._vod_extra_sweep_task
                    if task is not None:
                        await task
                    return refused, ok, remote.listing(REMOTE), 9 in server.active_recordings

    refused, ok, listing, started = run(go())
    assert refused and refused["code"] == "total_backlog" and not started, refused
    assert ok and len(listing) == 1 and listing[0].startswith("chunk_"), (ok, listing)


def test_the_sweep_runs_as_the_existing_start_and_clean_up_task_and_names_its_rules():
    src = (ROOT / "server.py").read_text()
    assert "self._start_vod_recovery()" in src and src.count("self._start_vod_recovery()") >= 2
    assert "asyncio.create_task(recover_vod_staging())" in src
    assert "never overwrite, never skip" in src.lower() or "never overwrite" in src
    assert "_vod_free_remote_name" not in src and "no_overwrite" not in src


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
