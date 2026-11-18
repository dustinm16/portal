"""Tests for the VOD staging folder. Run: venv/bin/python tests/test_vod_staging.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""
import asyncio
import errno
import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import vod_staging as vs  # noqa: E402

# The sandboxes below live under /tmp, which a custom staging folder may not;
# only the test that checks that rule puts the real value back.
REAL_TEMP_ROOTS = vs.TEMP_ROOTS
vs.TEMP_ROOTS = ()


def mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def tmp():
    return tempfile.TemporaryDirectory(prefix="vodtest_")


def make_session(base, name, chunks=("chunk_000.mkv",), remote="/v/s/2026-01-01", sidecar=True):
    d = Path(base) / name
    d.mkdir(parents=True)
    for c in chunks:
        (d / c).write_text("data-" + c)
    if sidecar:
        vs.write_sidecar(str(d), {"stream_id": 1, "user_id": 7, "stream_name": "s", "remote_session_dir": remote})
    return d


def test_config_default_is_outside_tmp_and_overridable():
    import importlib
    import config
    saved = os.environ.pop("VOD_TEMP_DIR", None)
    try:
        importlib.reload(config)
        default = config.Config.VOD_TEMP_DIR
        assert default == str(ROOT / "data" / "vod_tmp"), default
        assert not default.startswith("/tmp")
        os.environ["VOD_TEMP_DIR"] = "/var/lib/x/vods"
        importlib.reload(config)
        assert config.Config.VOD_TEMP_DIR == "/var/lib/x/vods"
        os.environ["VOD_TEMP_DIR"] = "rel/dir"
        importlib.reload(config)
        assert config.Config.VOD_TEMP_DIR == str(ROOT / "rel" / "dir")
    finally:
        if saved is None:
            os.environ.pop("VOD_TEMP_DIR", None)
        else:
            os.environ["VOD_TEMP_DIR"] = saved
        importlib.reload(config)


def test_ensure_private_dir_creates_0700_and_tightens():
    with tmp() as t:
        p = os.path.join(t, "data", "vod_tmp")
        old = os.umask(0)
        try:
            vs.ensure_private_dir(p)
        finally:
            os.umask(old)
        assert mode(p) == 0o700
        os.chmod(p, 0o755)
        vs.ensure_private_dir(p)
        assert mode(p) == 0o700


def test_ensure_private_dir_refuses_symlink_file_and_served_folder():
    with tmp() as t:
        real = os.path.join(t, "real")
        os.mkdir(real)
        link = os.path.join(t, "link")
        os.symlink(real, link)
        for bad in (link,):
            try:
                vs.ensure_private_dir(bad)
            except ValueError:
                pass
            else:
                raise AssertionError("symlink accepted")
        f = os.path.join(t, "file")
        Path(f).write_text("x")
        try:
            vs.ensure_private_dir(f)
        except ValueError:
            pass
        else:
            raise AssertionError("file accepted")
        static = os.path.join(t, "static")
        os.mkdir(static)
        for inside in (static, os.path.join(static, "uploads", "vods")):
            try:
                vs.ensure_private_dir(inside, (static,))
            except ValueError:
                pass
            else:
                raise AssertionError(f"{inside} accepted")
        # a symlink that points into the served folder is refused as a symlink
        os.symlink(static, os.path.join(t, "sneaky"))
        try:
            vs.ensure_private_dir(os.path.join(t, "sneaky"), (static,))
        except ValueError:
            pass
        else:
            raise AssertionError("symlink into static accepted")


def test_ensure_private_dir_refuses_foreign_owner():
    with tmp() as t:
        p = os.path.join(t, "d")
        os.mkdir(p)
        with mock.patch("vod_staging.os.geteuid", return_value=os.geteuid() + 1):
            try:
                vs.ensure_private_dir(p)
            except ValueError as e:
                assert "owned by" in str(e)
            else:
                raise AssertionError("foreign owner accepted")


def test_free_space_guard():
    with tmp() as t:
        ok, free = vs.has_free_space(t, 1)
        assert ok and free > 0
        ok, free = vs.has_free_space(t, 1 << 62)
        assert not ok
        with mock.patch("vod_staging.shutil.disk_usage") as du:
            du.return_value = mock.Mock(free=vs.MIN_FREE_BYTES - 1)
            assert vs.has_free_space(t)[0] is False
            du.return_value = mock.Mock(free=vs.MIN_FREE_BYTES)
            assert vs.has_free_space(t)[0] is True
    assert vs.MIN_FREE_BYTES == 1024 ** 3


def test_sidecar_roundtrip_and_rejects_junk():
    with tmp() as t:
        d = make_session(t, "1_2026-01-01_5")
        assert mode(d / vs.SIDECAR_NAME) == 0o600
        meta = vs.read_sidecar(str(d))
        assert meta["user_id"] == 7 and meta["remote_session_dir"] == "/v/s/2026-01-01"
        (d / vs.SIDECAR_NAME).write_text("not json")
        assert vs.read_sidecar(str(d)) is None
        (d / vs.SIDECAR_NAME).write_text('{"user_id": "7", "remote_session_dir": "/x"}')
        assert vs.read_sidecar(str(d)) is None
        (d / vs.SIDECAR_NAME).unlink()
        os.symlink(str(d / "chunk_000.mkv"), str(d / vs.SIDECAR_NAME))
        assert vs.read_sidecar(str(d)) is None
        try:
            vs.write_sidecar(str(d), {})
        except FileExistsError:
            pass
        else:
            raise AssertionError("sidecar written over an existing entry")


def test_migrate_rename_moves_sessions_and_never_overwrites():
    with tmp() as t:
        old = os.path.join(t, "old")
        new = os.path.join(t, "new")
        os.mkdir(old)
        os.mkdir(new)
        make_session(old, "1_a", chunks=("chunk_000.mkv", "chunk_001.mkv"))
        make_session(old, "2_b")
        make_session(new, "2_b", chunks=("chunk_000.mkv",))
        (Path(new) / "2_b" / "chunk_000.mkv").write_text("NEW-KEEP")
        res = vs.migrate_legacy(new, old)
        assert res["moved"] == ["1_a"], res
        assert [n for n, _ in res["skipped"]] == ["2_b"], res
        assert (Path(new) / "1_a" / "chunk_001.mkv").read_text() == "data-chunk_001.mkv"
        assert (Path(new) / "2_b" / "chunk_000.mkv").read_text() == "NEW-KEEP"
        assert (Path(old) / "2_b" / "chunk_000.mkv").exists(), "colliding source must stay"
        assert not (Path(old) / "1_a").exists()
        assert mode(Path(new) / "1_a") == 0o700


def test_migrate_copy_fallback_across_filesystems():
    with tmp() as t:
        old = os.path.join(t, "old")
        new = os.path.join(t, "new")
        os.mkdir(old)
        os.mkdir(new)
        s = make_session(old, "1_a", chunks=("chunk_000.mkv",))
        outside = Path(t) / "secret.txt"
        outside.write_text("secret")
        os.symlink(str(outside), str(s / "chunk_009.mkv"))
        os.mkfifo(str(s / "fifo"))
        real_rename = os.rename

        def exdev(src, dst, *a, **k):
            raise OSError(errno.EXDEV, "cross-device")

        with mock.patch("vod_staging.os.rename", side_effect=exdev):
            res = vs.migrate_legacy(new, old)
        assert os.rename is real_rename
        assert res["moved"] == ["1_a"], res
        moved = Path(new) / "1_a"
        assert (moved / "chunk_000.mkv").read_text() == "data-chunk_000.mkv"
        assert mode(moved / "chunk_000.mkv") == 0o600
        assert not (moved / "chunk_009.mkv").exists(), "symlink was followed or copied"
        assert not (moved / "fifo").exists()
        assert outside.read_text() == "secret"
        assert not os.path.exists(old), "legacy folder should be gone once emptied"


def test_migrate_copy_failure_keeps_source_and_cleans_target():
    with tmp() as t:
        old = os.path.join(t, "old")
        new = os.path.join(t, "new")
        os.mkdir(old)
        os.mkdir(new)
        make_session(old, "1_a")

        def exdev(src, dst, *a, **k):
            raise OSError(errno.EXDEV, "cross-device")

        with mock.patch("vod_staging.os.rename", side_effect=exdev), \
                mock.patch("vod_staging._copy_tree_nofollow", side_effect=OSError(errno.ENOSPC, "full")):
            res = vs.migrate_legacy(new, old)
        assert res["moved"] == [] and len(res["skipped"]) == 1
        assert (Path(old) / "1_a" / "chunk_000.mkv").exists()
        assert not (Path(new) / "1_a").exists()


def test_migrate_ignores_symlinked_or_foreign_legacy_dir():
    with tmp() as t:
        real = os.path.join(t, "real")
        new = os.path.join(t, "new")
        os.mkdir(real)
        os.mkdir(new)
        make_session(real, "1_a")
        link = os.path.join(t, "old")
        os.symlink(real, link)
        res = vs.migrate_legacy(new, link)
        assert res["moved"] == [] and res["skipped"], res
        assert (Path(real) / "1_a").exists()
        os.unlink(link)
        os.rename(real, link)
        with mock.patch("vod_staging.os.geteuid", return_value=os.geteuid() + 1):
            res = vs.migrate_legacy(new, link)
        assert res["moved"] == [], res
        assert (Path(link) / "1_a").exists()
        assert vs.migrate_legacy(new, os.path.join(t, "absent")) == {"moved": [], "skipped": []}


def test_migrate_skips_symlinked_session_entry():
    with tmp() as t:
        old = os.path.join(t, "old")
        new = os.path.join(t, "new")
        target = os.path.join(t, "target")
        for d in (old, new, target):
            os.mkdir(d)
        os.symlink(target, os.path.join(old, "evil"))
        res = vs.migrate_legacy(new, old)
        assert res["moved"] == [] and res["skipped"] == [("evil", "symbolic link")], res
        assert os.listdir(new) == []


def test_next_free_chunk_number_counts_other_sessions_for_same_remote():
    with tmp() as t:
        make_session(t, "1_a", chunks=("chunk_003.mkv", "chunk_005.mkv"), remote="/r/2026-01-01")
        make_session(t, "1_b", chunks=("chunk_009.mkv",), remote="/r/other")
        cur = make_session(t, "1_c", chunks=("chunk_020.mkv",), remote="/r/2026-01-01")
        assert vs.next_free_chunk_number(t, "/r/2026-01-01") == 21
        assert vs.next_free_chunk_number(t, "/r/2026-01-01", current_dir=str(cur)) == 6
        assert vs.next_free_chunk_number(t, "/r/none") == 0


def test_remove_if_empty_keeps_chunks():
    with tmp() as t:
        d = make_session(t, "1_a", chunks=("chunk_000.mkv",))
        assert vs.remove_if_empty(str(d)) is False and d.exists()
        (d / "chunk_000.mkv").unlink()
        assert vs.remove_if_empty(str(d)) is True and not d.exists()


class FakeSftp:
    """Remote store keyed by path; stat raises SFTPNoSuchFile when absent."""

    def __init__(self, existing=()):
        import asyncssh
        self._exc = asyncssh.SFTPNoSuchFile
        self.files = {p: "old" for p in existing}
        self.dirs = set()
        self.renames = []
        self.put_names = []

    async def stat(self, path):
        if path in self.files or path in self.dirs:
            return object()
        raise self._exc("no such file")

    async def mkdir(self, path):
        self.dirs.add(path)

    async def put(self, local, remote):
        self.put_names.append(remote)
        if self.put_fail or self.put_hang:
            self.files[remote] = Path(local).read_text()[:3]  # truncated
            if self.put_hang:
                await asyncio.sleep(3600)
            raise self.put_fail
        self.files[remote] = Path(local).read_text()

    # Hooks for the interrupted-upload tests; the defaults behave like a healthy server.
    put_fail = None      # exception to raise after a truncated file was written
    put_hang = False     # write a truncated file, then never finish
    posix_ok = True
    rename_fails = False

    async def remove(self, path):
        if path not in self.files:
            raise self._exc("no such file")
        del self.files[path]

    async def rename(self, old, new):
        if self.rename_fails:
            raise OSError("rename failed")
        if new in self.files:
            raise OSError("destination exists")
        self.files[new] = self.files.pop(old)
        self.renames.append(("rename", old, new))

    async def posix_rename(self, old, new):
        if not self.posix_ok:
            import asyncssh
            raise asyncssh.SFTPOpUnsupported("no posix-rename extension")
        if self.rename_fails:
            raise OSError("rename failed")
        self.files[new] = self.files.pop(old)
        self.renames.append(("posix_rename", old, new))


def _server_module():
    # server.py is large but importable; it needs no network on import.
    import server
    return server


class FakeDb:
    """Owner and storage lookups for recovery; set missing_users / missing_storage / raises."""
    def __init__(self, missing_users=(), missing_storage=(), raises=False):
        self.missing_users = set(missing_users)
        self.missing_storage = set(missing_storage)
        self.raises = raises

    async def get_user_by_id(self, uid):
        if self.raises:
            raise RuntimeError("database is locked")
        return None if uid in self.missing_users else {"id": uid}

    async def get_vod_storage(self, uid):
        if self.raises:
            raise RuntimeError("database is locked")
        return None if uid in self.missing_storage else {"remote_path": "/v"}


class LogCapture:
    def __enter__(self):
        import logging
        self.records = []
        outer = self

        class H(logging.Handler):
            def emit(self, record):
                outer.records.append(record.getMessage())

        self.h = H(level=logging.DEBUG)
        self.log = logging.getLogger("portal")
        self.old_level = self.log.level
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(self.h)
        return self

    def __exit__(self, *a):
        self.log.removeHandler(self.h)
        self.log.setLevel(self.old_level)

    def text(self):
        return "\n".join(self.records)


def age(path, days):
    """Backdate a session folder's chunks and record by *days*."""
    import time
    t = time.time() - days * 86400
    for name in os.listdir(path):
        os.utime(os.path.join(path, name), (t, t))


def test_recovery_uploads_without_overwriting_and_cleans_up():
    server = _server_module()
    with tmp() as t:
        d1 = make_session(t, "1_2026-01-01_5", chunks=("chunk_005.mkv", "chunk_006.mkv"), remote="/v/s/2026-01-01")
        d2 = make_session(t, "2_x", chunks=(), remote="/v/x")
        d3 = make_session(t, "3_nosidecar", chunks=("chunk_000.mkv",), sidecar=False)
        (d1 / "chunk_007.mkv").write_text("")  # empty chunk: dropped, must not keep the folder
        sftp = FakeSftp(existing=["/v/s/2026-01-01/chunk_005.mkv"])

        async def fake_connect(user_id):
            assert user_id == 7
            return mock.Mock(), sftp, None

        async def go():
            with mock.patch.object(server, "_connect_vod_sftp", fake_connect), mock.patch.object(server, "db", FakeDb()):
                await server.recover_vod_staging(vod_staging_dirs)

        vod_staging_dirs = vs.list_session_dirs(t)
        asyncio.run(go())
        assert sftp.files["/v/s/2026-01-01/chunk_005.mkv"] == "old", "existing remote chunk was overwritten"
        assert sftp.files["/v/s/2026-01-01/chunk_005_recovered1.mkv"] == "data-chunk_005.mkv"
        assert sftp.files["/v/s/2026-01-01/chunk_006.mkv"] == "data-chunk_006.mkv"
        assert not d1.exists(), "uploaded session folder should be removed"
        assert not d2.exists(), "empty session folder should be removed"
        assert (d3 / "chunk_000.mkv").exists(), "folder without a session record must be left alone"


def test_recovery_keeps_chunks_when_upload_fails():
    server = _server_module()
    with tmp() as t:
        d1 = make_session(t, "1_a", chunks=("chunk_000.mkv",))

        async def fail_connect(user_id):
            return None, None, "connection refused"

        async def go():
            with mock.patch.object(server, "_connect_vod_sftp", fail_connect), mock.patch.object(server, "db", FakeDb()):
                await server.recover_vod_staging(vs.list_session_dirs(t))

        asyncio.run(go())
        assert (d1 / "chunk_000.mkv").exists()
        assert vs.read_sidecar(str(d1)) is not None


def test_recovery_skips_session_that_is_recording():
    server = _server_module()
    with tmp() as t:
        d1 = make_session(t, "1_a", chunks=("chunk_000.mkv",))
        calls = []

        async def fake_connect(user_id):
            calls.append(user_id)
            return None, None, "x"

        async def go():
            server.active_recordings[1] = {"session_dir": str(d1)}
            try:
                with mock.patch.object(server, "_connect_vod_sftp", fake_connect), mock.patch.object(server, "db", FakeDb()):
                    await server.recover_vod_staging([str(d1)])
            finally:
                server.active_recordings.pop(1, None)

        asyncio.run(go())
        assert calls == [] and (d1 / "chunk_000.mkv").exists()


def test_start_refuses_when_free_space_low_and_logs_it():
    server = _server_module()
    with tmp() as t:
        stream = {"id": 9, "user_id": 7, "name": "My Show", "owner_username": "owner"}
        logged = []

        class FakeDb:
            async def get_vod_storage(self, uid):
                return {"remote_path": "/v"}

            async def log_activity(self, *a, **k):
                logged.append(a)

        async def mtx():
            return {"x": 1}

        async def go():
            with mock.patch.object(server, "VOD_TEMP_DIR", os.path.join(t, "stage")), \
                    mock.patch.object(server, "db", FakeDb()), \
                    mock.patch.object(server, "_get_mediamtx_config", mtx), \
                    mock.patch.object(server, "VOD_MIN_FREE_BYTES", 1 << 62), \
                    mock.patch.object(server.asyncio, "create_subprocess_exec",
                                      side_effect=AssertionError("ffmpeg must not start")):
                await server.start_vod_recording(stream, "live_x")

        asyncio.run(go())
        assert 9 not in server.active_recordings
        assert len(logged) == 1 and logged[0][2] == "vod_skipped" and "free" in logged[0][3], logged
        stage = os.path.join(t, "stage")
        assert [n for n in os.listdir(stage) if n != vs.MARKER_NAME] == [], "no session folder may be created when refusing"


def _upload(server, t, sftp, name="chunk_000.mkv", no_overwrite=False, timeout=None):
    """Run the real chunk upload for one local chunk against *sftp*; return (recording, error)."""
    d = make_session(t, "1_a", chunks=(name,))
    rec = {"session_dir": str(d), "remote_session_dir": "/v/s/2026-01-01", "user_id": 7,
           "stream_name": "s", "uploaded": set()}

    async def connect(uid):
        class Conn:
            def close(self):
                pass
        return Conn(), sftp, None

    real_wait_for = asyncio.wait_for

    async def short_wait_for(coro, timeout=None):
        return await real_wait_for(coro, timeout=0.2 if timeout_short else timeout)

    timeout_short = timeout is not None

    async def go():
        with mock.patch.object(server, "_connect_vod_sftp", connect), \
                mock.patch.object(server.asyncio, "wait_for", short_wait_for):
            await server._do_vod_chunk_upload(rec, final=True, no_overwrite=no_overwrite)

    with LogCapture() as cap:
        asyncio.run(go())
    return rec, d, cap.text()


def test_upload_goes_to_a_part_name_and_is_renamed_on_success():
    server = _server_module()
    final = "/v/s/2026-01-01/chunk_000.mkv"
    with tmp() as t:
        sftp = FakeSftp()
        rec, d, log = _upload(server, t, sftp)
        assert sftp.put_names == [final + ".part"], sftp.put_names
        assert sftp.renames == [("posix_rename", final + ".part", final)], sftp.renames
        assert list(sftp.files) == [final] and sftp.files[final] == "data-chunk_000.mkv"
        assert not (d / "chunk_000.mkv").exists() and str(d / "chunk_000.mkv") in rec["uploaded"]
    # a server without the posix-rename extension falls back to the plain rename
    with tmp() as t:
        sftp = FakeSftp()
        sftp.posix_ok = False
        _upload(server, t, sftp)
        assert sftp.renames == [("rename", final + ".part", final)] and list(sftp.files) == [final]
    # recovery uses the same function and the same rule, with its _recovered name
    with tmp() as t:
        sftp = FakeSftp(existing=[final])
        _upload(server, t, sftp, no_overwrite=True)
        rec_name = "/v/s/2026-01-01/chunk_000_recovered1.mkv"
        assert sftp.put_names == [rec_name + ".part"], sftp.put_names
        assert sftp.files[final] == "old" and sftp.files[rec_name] == "data-chunk_000.mkv"
        assert not any(n.endswith(".part") for n in sftp.files)


def test_failed_upload_leaves_no_remote_partial_and_keeps_the_local_chunk():
    server = _server_module()
    final = "/v/s/2026-01-01/chunk_000.mkv"
    # the put fails half way
    with tmp() as t:
        sftp = FakeSftp()
        sftp.put_fail = OSError("connection reset")
        rec, d, log = _upload(server, t, sftp)
        assert sftp.files == {}, sftp.files
        assert (d / "chunk_000.mkv").exists() and not rec["uploaded"]
        assert "upload failed" in log, log
    # the put hangs and times out
    with tmp() as t:
        sftp = FakeSftp()
        sftp.put_hang = True
        rec, d, log = _upload(server, t, sftp, timeout=0.2)
        assert sftp.files == {}, sftp.files
        assert (d / "chunk_000.mkv").exists() and "timed out" in log, log
    # the rename fails after a complete put: the partial is removed, nothing under the final name
    with tmp() as t:
        sftp = FakeSftp()
        sftp.rename_fails = True
        rec, d, log = _upload(server, t, sftp)
        assert sftp.files == {}, sftp.files
        assert (d / "chunk_000.mkv").exists() and not rec["uploaded"]
    # a cancelled upload removes its partial and lets the cancellation through
    with tmp() as t:
        sftp = FakeSftp()
        sftp.put_hang = True
        d = make_session(t, "1_a")
        rec = {"session_dir": str(d), "remote_session_dir": "/v/s/2026-01-01", "user_id": 7,
               "stream_name": "s", "uploaded": set()}

        async def connect(uid):
            class Conn:
                def close(self):
                    pass
            return Conn(), sftp, None

        async def go():
            with mock.patch.object(server, "_connect_vod_sftp", connect):
                task = asyncio.create_task(server._do_vod_chunk_upload(rec, final=True))
                await asyncio.sleep(0.2)
                assert final + ".part" in sftp.files, "the truncated partial should exist while the put hangs"
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    return True
                return False

        assert asyncio.run(go()) is True
        assert sftp.files == {}, sftp.files
        assert (d / "chunk_000.mkv").exists()


# ---------------------------------------------------------------------------
# Dangerous staging folders
# ---------------------------------------------------------------------------

def _refused(path, **kw):
    try:
        vs.ensure_private_dir(path, **kw)
    except ValueError as e:
        return str(e)
    return None


def test_dangerous_locations_are_refused_and_left_untouched():
    with tmp() as t:
        root = os.path.join(t, "project")
        os.mkdir(root)
        home = os.path.join(t, "home")
        os.mkdir(home)
        expected = {
            "/": "the filesystem root",
            "/tmp": "a shared temporary folder",
            "/var/tmp": "a shared temporary folder",
            root: "the portal's project folder",
        }
        for path, why in expected.items():
            assert why in (vs.dangerous_reason(path, root) or ""), f"{path}: {vs.dangerous_reason(path, root)}"
            assert why in (_refused(path, project_root=root) or ""), f"{path} accepted or refused for another reason"
        with mock.patch.dict(os.environ, {"HOME": home}):
            assert "home directory" in _refused(home, project_root=root)
        mnt = os.path.join(t, "mnt")
        os.mkdir(mnt)
        with mock.patch("vod_staging.os.path.ismount", lambda p: os.path.realpath(p) == os.path.realpath(mnt)):
            assert "mounted filesystem" in _refused(mnt, project_root=root)
        # a symlink to a dangerous place is refused too
        os.symlink("/tmp", os.path.join(t, "lnk"))
        assert _refused(os.path.join(t, "lnk"), project_root=root)
        # nothing was changed: no marker in any refused folder, mode intact
        assert not os.path.exists(os.path.join(mnt, vs.MARKER_NAME))
        assert not os.path.exists(os.path.join(home, vs.MARKER_NAME))
        assert not os.path.exists(os.path.join(root, vs.MARKER_NAME))
        assert not os.path.exists(os.path.join("/tmp", vs.MARKER_NAME))


def test_folders_below_tmp_and_var_tmp_are_refused_and_left_untouched():
    with tmp() as t:
        with mock.patch.object(vs, "TEMP_ROOTS", REAL_TEMP_ROOTS):
            assert vs.TEMP_ROOTS == ("/tmp", "/var/tmp")
            for path in ("/tmp/portal_vods", "/tmp/a/b/vods", "/var/tmp/vods", "/var/tmp/x/y"):
                existed = os.path.exists(path)
                why = vs.dangerous_reason(path) or ""
                assert "PrivateTmp" in why and path.split("/")[1] in why, (path, why)
                assert "PrivateTmp" in (_refused(path) or ""), path
                assert os.path.exists(path) == existed, f"{path} was created"
            # the sandbox itself is below /tmp
            inside = os.path.join(t, "stage")
            assert "PrivateTmp" in (_refused(inside) or "")
            assert not os.path.exists(inside)
            for ok in ("/var/lib/vods", "/srv/vods", "/tmpfoo/vods", "/var/tmpfoo", "/home/x/vods"):
                assert vs.dangerous_reason(ok) is None, ok
        # the exact shared folders keep their own message
        assert "shared temporary" in vs.dangerous_reason("/tmp")


def test_default_folder_below_tmp_is_still_used_but_a_custom_sibling_is_refused():
    server = _server_module()
    Config = server.Config
    saved = Config.VOD_TEMP_DIR
    with tmp() as t, mock.patch.object(vs, "TEMP_ROOTS", REAL_TEMP_ROOTS):
        default = os.path.join(t, "project", "data", "vod_tmp")
        try:
            # the project (and so its default folder) lives below /tmp
            assert vs.dangerous_reason(default, os.path.join(t, "project")) is not None
            assert vs.dangerous_reason(default, os.path.join(t, "project"), allow_temp=True) is None
            # configured == default: used
            chosen, cfg, log = _prepare_in(server, t, default)
            assert chosen == default and vs.has_marker(default) and "refused" not in log, log
            assert server._vod_staging_usable is True
            # a custom folder next to it: refused, default used, custom left alone
            custom = os.path.join(t, "project", "data", "custom")
            chosen, cfg, log = _prepare_in(server, t, custom)
            assert chosen == default and "refused" in log and "PrivateTmp" in log, log
            assert not os.path.exists(custom)
            assert server._vod_staging_usable is True

            # a new recording may still start its session folder in the default
            logged = []

            class Db:
                async def get_vod_storage(self, uid):
                    return {"remote_path": "/v"}

                async def log_activity(self, *a, **k):
                    logged.append(a)

            async def mtx():
                return {"x": 1}

            async def go():
                with mock.patch.object(server, "VOD_TEMP_DIR", default), \
                        mock.patch.object(Config, "VOD_TEMP_DIR_DEFAULT", default), \
                        mock.patch.object(server, "_PROJECT_ROOT", os.path.join(t, "project")), \
                        mock.patch.object(server, "db", Db()), \
                        mock.patch.object(server, "_get_mediamtx_config", mtx), \
                        mock.patch.object(server, "VOD_MIN_FREE_BYTES", 1 << 62):  # stop right after the checks
                    await server.start_vod_recording(
                        {"id": 9, "user_id": 7, "name": "Show", "owner_username": "o"}, "live_x")

            asyncio.run(go())
            assert len(logged) == 1 and "free" in logged[0][3] and "not usable" not in logged[0][3], logged
        finally:
            Config.VOD_TEMP_DIR = saved


def test_nonempty_folder_without_marker_is_refused_and_never_changed():
    with tmp() as t:
        d = os.path.join(t, "shared")
        os.makedirs(os.path.join(d, "empty_sub"))
        Path(d, "notes.txt").write_text("mine")
        os.chmod(d, 0o755)
        with mock.patch("vod_staging.os.chmod", side_effect=AssertionError("chmod on a refused folder")):
            msg = _refused(d)
        assert msg and "not empty" in msg and "not created by the portal" in msg, msg
        assert mode(d) == 0o755
        assert sorted(os.listdir(d)) == ["empty_sub", "notes.txt"], "refused folder was changed"
        # recovery must never be pointed at it either: the refusal is the only guard
        assert vs.read_sidecar(os.path.join(d, "empty_sub")) is None


def test_empty_folder_is_adopted_and_marked_and_marked_folder_is_reused():
    with tmp() as t:
        d = os.path.join(t, "mine")
        os.mkdir(d)
        os.chmod(d, 0o755)
        vs.ensure_private_dir(d)
        assert mode(d) == 0o700 and vs.has_marker(d)
        assert mode(os.path.join(d, vs.MARKER_NAME)) == 0o600
        make_session(d, "1_a")
        vs.ensure_private_dir(d)  # non-empty but marked: fine
        # a folder the portal creates itself is marked
        new = os.path.join(t, "deep", "new")
        vs.ensure_private_dir(new)
        assert vs.has_marker(new)
        # the portal's own default may be adopted when files are already there
        old = os.path.join(t, "old")
        os.mkdir(old)
        Path(old, "x").write_text("x")
        assert _refused(old)
        vs.ensure_private_dir(old, adopt_nonempty=True)
        assert vs.has_marker(old)


def test_marker_is_not_a_session_and_does_not_count_as_a_chunk():
    with tmp() as t:
        vs.ensure_private_dir(os.path.join(t, "d"))
        assert vs.list_session_dirs(os.path.join(t, "d")) == []


def _prepare_in(server, t, configured, default=None):
    """Run the real startup selection in a sandbox; return (chosen, config value, log text)."""
    Config = server.Config  # not config.Config: another test reloads that module
    default = default or os.path.join(t, "project", "data", "vod_tmp")
    saved = Config.VOD_TEMP_DIR, Config.VOD_TEMP_DIR_DEFAULT
    try:
        Config.VOD_TEMP_DIR_DEFAULT = default
        with mock.patch.object(server, "VOD_TEMP_DIR", configured), \
                mock.patch.object(server, "_PROJECT_ROOT", os.path.join(t, "project")), \
                mock.patch.object(vs, "migrate_legacy", lambda d: {"moved": [], "skipped": []}), \
                LogCapture() as cap:
            server._vod_prepare_staging()
            return server.VOD_TEMP_DIR, Config.VOD_TEMP_DIR, cap.text()
    finally:
        Config.VOD_TEMP_DIR, Config.VOD_TEMP_DIR_DEFAULT = saved


def test_startup_falls_back_to_default_for_refused_folder_and_logs_it():
    server = _server_module()
    Config = server.Config
    with tmp() as t:
        default = os.path.join(t, "project", "data", "vod_tmp")
        bad = os.path.join(t, "shared")
        os.makedirs(os.path.join(bad, "empty_sub"))
        Path(bad, "f").write_text("f")
        os.chmod(bad, 0o755)
        saved = Config.VOD_TEMP_DIR
        try:
            with mock.patch("vod_staging.os.chmod", wraps=os.chmod) as ch:
                chosen, cfg, log = _prepare_in(server, t, bad)
                assert all(c.args[0] != bad for c in ch.call_args_list), "chmod on the refused folder"
            assert chosen == default and cfg == default, (chosen, cfg)
            assert "refused" in log and bad in log and "using the default" in log, log
            assert vs.has_marker(default)
            assert mode(bad) == 0o755 and sorted(os.listdir(bad)) == ["empty_sub", "f"]
            # a good custom folder is kept
            good = os.path.join(t, "good")
            chosen, cfg, log = _prepare_in(server, t, good)
            assert chosen == good and vs.has_marker(good) and "refused" not in log
            # the project root, a home directory and /tmp are refused at startup
            for path in (os.path.join(t, "project"), "/tmp", "/"):
                chosen, cfg, log = _prepare_in(server, t, path)
                assert chosen == default and "refused" in log, (path, chosen, log)
            # the default location is adopted even if an earlier run left files in it
            Path(default, "leftover").write_text("x")
            os.unlink(os.path.join(default, vs.MARKER_NAME))
            chosen, cfg, log = _prepare_in(server, t, "/")
            assert chosen == default and vs.has_marker(default)
        finally:
            Config.VOD_TEMP_DIR = saved


def _tree_state(root):
    """Everything observable about a tree: type, mode, mtime, size, bytes, link target."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames + ["."]:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            entry = [stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_mtime_ns, st.st_size]
            if stat.S_ISREG(st.st_mode):
                entry.append(Path(p).read_bytes())
            elif stat.S_ISLNK(st.st_mode):
                entry.append(os.readlink(p))
            out[os.path.relpath(p, root)] = entry
    return out


def _fill_refused(folder):
    """A folder with everything the recovery would otherwise remove or upload."""
    os.makedirs(os.path.join(folder, "empty_sub"))
    zero = make_session(folder, "2_zero", chunks=())
    (zero / "chunk_000.mkv").write_bytes(b"")
    old = make_session(folder, "3_old", chunks=("chunk_000.mkv",), sidecar=False)
    age(old, 30)
    make_session(folder, "4_live", chunks=("chunk_000.mkv", "chunk_001.mkv"))
    Path(folder, "notes.txt").write_text("mine")
    os.chmod(folder, 0o755)
    os.utime(os.path.join(folder, "empty_sub"), (1000, 1000))


def _refused_everywhere(server, t, configured, default):
    """Run start-up, then every path that could touch the folder; return (log text, observations)."""
    Config = server.Config
    saved = Config.VOD_TEMP_DIR, Config.VOD_TEMP_DIR_DEFAULT
    calls = []
    logged = []

    async def connect(uid):
        calls.append(uid)
        return None, None, "must not be called"

    class Db(FakeDb):
        async def get_vod_storage(self, uid):
            return {"remote_path": "/v"}

        async def log_activity(self, *a, **k):
            logged.append(a)

    async def mtx():
        return {"x": 1}

    async def go():
        with mock.patch.object(server, "_connect_vod_sftp", connect), \
                mock.patch.object(server, "db", Db()), \
                mock.patch.object(server, "_get_mediamtx_config", mtx), \
                mock.patch.object(server.asyncio, "create_subprocess_exec",
                                  side_effect=AssertionError("ffmpeg must not start")):
            await server.recover_vod_staging()
            await server.recover_vod_staging([os.path.join(configured, "3_old"), os.path.join(configured, "empty_sub")])
            await server.start_vod_recording({"id": 9, "user_id": 7, "name": "Show", "owner_username": "o"}, "live_x")

    try:
        Config.VOD_TEMP_DIR_DEFAULT = default
        with mock.patch.object(server, "VOD_TEMP_DIR", configured), \
                mock.patch.object(server, "_PROJECT_ROOT", os.path.join(t, "project")), \
                mock.patch.object(vs, "migrate_legacy", side_effect=AssertionError("migration must not run")), \
                LogCapture() as cap:
            leftovers = server._vod_prepare_staging()
            usable = getattr(server, "_vod_staging_usable", None)
            asyncio.run(go())
            return cap.text(), {
                "leftovers": leftovers, "usable": usable, "calls": calls, "logged": logged,
                "recording": 9 in server.active_recordings, "running": server._vod_recovery_running,
            }
    finally:
        server._vod_staging_usable = True
        Config.VOD_TEMP_DIR, Config.VOD_TEMP_DIR_DEFAULT = saved


def _check_nothing_happened(seen):
    assert seen["leftovers"] == [] and seen["usable"] is False, seen
    assert seen["calls"] == [], "no upload may be attempted"
    assert not seen["recording"] and not seen["running"]
    assert len(seen["logged"]) == 1 and seen["logged"][0][2] == "vod_skipped" and "staging" in seen["logged"][0][3], seen


def test_no_usable_staging_folder_leaves_the_refused_folder_byte_for_byte_untouched():
    server = _server_module()
    # (a) configured folder refused and the default is a symlink, so also refused
    with tmp() as t:
        os.makedirs(os.path.join(t, "project", "data"))
        bad = os.path.join(t, "shared")
        _fill_refused(bad)
        elsewhere = os.path.join(t, "elsewhere")
        _fill_refused(elsewhere)
        default = os.path.join(t, "project", "data", "vod_tmp")
        os.symlink(elsewhere, default)
        before, before_else = _tree_state(bad), _tree_state(elsewhere)
        log, seen = _refused_everywhere(server, t, bad, default)
        assert _tree_state(bad) == before, "refused folder changed"
        assert _tree_state(elsewhere) == before_else, "the default's target changed"
        _check_nothing_happened(seen)
        assert "refused" in log and "not usable" in log and "recovery skipped" in log, log
        assert "VOD recording not started" in log, log
    # (b) the default itself is refused (a symlink) and is the configured folder
    with tmp() as t:
        os.makedirs(os.path.join(t, "project", "data"))
        target = os.path.join(t, "target")
        _fill_refused(target)
        default = os.path.join(t, "project", "data", "vod_tmp")
        os.symlink(target, default)
        before = _tree_state(target)
        log, seen = _refused_everywhere(server, t, default, default)
        assert _tree_state(target) == before, "refused folder changed"
        _check_nothing_happened(seen)
        assert "not usable" in log and "is a symbolic link" in log, log
    assert server._vod_staging_usable is True


def test_usable_state_comes_back_when_a_folder_is_usable():
    server = _server_module()
    with tmp() as t:
        _prepare_in(server, t, os.path.join(t, "good"))
        assert server._vod_staging_usable is True


# ---------------------------------------------------------------------------
# Periodic recovery
# ---------------------------------------------------------------------------

def test_recovery_passes_never_overlap_and_relist_each_time():
    server = _server_module()
    with tmp() as t:
        make_session(t, "1_a", chunks=("chunk_000.mkv",))
        make_session(t, "2_b", chunks=("chunk_000.mkv",), remote="/v/other")
        sftp = FakeSftp()
        connects = []

        async def go():
            gate = asyncio.Event()
            entered = asyncio.Event()

            async def slow_connect(uid):
                connects.append(uid)
                entered.set()
                await gate.wait()
                return mock.Mock(), sftp, None

            with mock.patch.object(server, "_connect_vod_sftp", slow_connect), \
                    mock.patch.object(server, "db", FakeDb()), \
                    mock.patch.object(server, "VOD_TEMP_DIR", t):
                first = asyncio.create_task(server.recover_vod_staging())
                await entered.wait()
                assert server._vod_recovery_running
                await server.recover_vod_staging()  # second pass while the first is blocked
                assert len(connects) == 1, f"two recoveries ran at once: {connects}"
                gate.set()
                await first
                assert not server._vod_recovery_running
                # a later pass lists the folder again and finds a new leftover
                make_session(t, "3_c", chunks=("chunk_000.mkv",), remote="/v/third")
                await server.recover_vod_staging()

        asyncio.run(go())
        assert len(connects) == 3, connects  # 2 folders in pass one, 1 new folder in pass two
        assert sorted(sftp.files) == ["/v/other/chunk_000.mkv", "/v/s/2026-01-01/chunk_000.mkv", "/v/third/chunk_000.mkv"]


def test_recovery_flag_is_released_after_an_error():
    server = _server_module()

    async def go():
        with mock.patch.object(server, "_vod_recover_one", side_effect=RuntimeError("boom")):
            try:
                await server.recover_vod_staging(["/nonexistent/x"])
            except RuntimeError:
                pass
        assert not server._vod_recovery_running

    asyncio.run(go())


def test_recovery_skips_folders_a_recording_is_still_finishing():
    server = _server_module()
    with tmp() as t:
        d = make_session(t, "1_a", chunks=("chunk_000.mkv",))
        calls = []

        async def fake_connect(uid):
            calls.append(uid)
            return None, None, "x"

        async def go():
            server._vod_busy_dirs.add(str(d))  # popped from active_recordings, upload still running
            try:
                with mock.patch.object(server, "_connect_vod_sftp", fake_connect), \
                        mock.patch.object(server, "db", FakeDb()):
                    await server.recover_vod_staging([str(d)])
            finally:
                server._vod_busy_dirs.discard(str(d))

        asyncio.run(go())
        assert calls == [] and (d / "chunk_000.mkv").exists()


def test_recording_marks_its_folder_busy_until_cleanup():
    server = _server_module()
    with tmp() as t:
        stream = {"id": 9, "user_id": 7, "name": "My Show", "owner_username": "owner"}

        class Db:
            async def get_vod_storage(self, uid):
                return {"remote_path": "/v"}

            async def log_activity(self, *a, **k):
                pass

        async def mtx():
            return {"x": 1}

        async def no_sftp(uid):
            return None, None, "x"

        async def noop(*a, **k):
            return None

        class Proc:
            returncode = None
            stderr = None

            async def wait(self):
                return 0

        async def ok_exec(*a, **k):
            return Proc()

        async def missing_exec(*a, **k):
            raise FileNotFoundError("ffmpeg")

        async def go(executor):
            with mock.patch.object(server, "VOD_TEMP_DIR", os.path.join(t, "stage")), \
                    mock.patch.object(server, "db", Db()), \
                    mock.patch.object(server, "_get_mediamtx_config", mtx), \
                    mock.patch.object(server, "_connect_vod_sftp", no_sftp), \
                    mock.patch.object(server, "_vod_chunk_uploader", noop), \
                    mock.patch.object(server, "VOD_MIN_FREE_BYTES", 1), \
                    mock.patch.object(server, "_PROJECT_ROOT", t), \
                    mock.patch.object(server.asyncio, "sleep", noop), \
                    mock.patch.object(server.asyncio, "create_subprocess_exec", executor):
                await server.start_vod_recording(stream, "live_x")

        asyncio.run(go(missing_exec))
        assert not server._vod_busy_dirs, "a failed start left its folder marked busy"
        assert [n for n in os.listdir(os.path.join(t, "stage")) if n != vs.MARKER_NAME] == []
        asyncio.run(go(ok_exec))
        try:
            assert len(server._vod_busy_dirs) == 1 and 9 in server.active_recordings
            sd = next(iter(server._vod_busy_dirs))
            server.active_recordings.pop(9, None)
            server._vod_cleanup_session_dir(sd)
            assert not server._vod_busy_dirs, "cleanup did not release the folder"
        finally:
            server.active_recordings.pop(9, None)
            server._vod_busy_dirs.clear()


def test_cancel_vod_recovery_ends_a_hanging_pass_and_releases_the_guard():
    server = _server_module()

    async def go():
        srv = server.PortalServer()
        started = asyncio.Event()

        with tmp() as t:
            make_session(t, "1_a", chunks=("chunk_000.mkv",))

            async def never(uid):
                started.set()
                await asyncio.sleep(3600)

            with mock.patch.object(server, "_connect_vod_sftp", never), \
                    mock.patch.object(server, "db", FakeDb()), \
                    mock.patch.object(server, "VOD_TEMP_DIR", t):
                srv._start_vod_recovery()
                task = srv._vod_recovery_task
                await started.wait()
                assert server._vod_recovery_running
                await srv._cancel_vod_recovery()
                assert task.cancelled() or task.done()
                assert srv._vod_recovery_task is None
                assert not server._vod_recovery_running, "the guard stayed set after a cancel"
                await srv._cancel_vod_recovery()  # nothing running: harmless
            assert os.path.exists(os.path.join(t, "1_a", "chunk_000.mkv")), "a cancelled pass lost a chunk"

    asyncio.run(go())


def test_server_runs_recovery_as_one_tracked_task_and_stop_cancels_it():
    server = _server_module()

    async def go():
        srv = server.PortalServer()
        assert srv._vod_recovery_task is None
        started = asyncio.Event()

        async def hang(*a, **k):
            started.set()
            await asyncio.sleep(3600)

        with mock.patch.object(server, "recover_vod_staging", hang):
            srv._start_vod_recovery()
            srv._start_vod_recovery()  # the cleanup loop calling again while one task exists
            task = srv._vod_recovery_task
            await started.wait()
            srv._start_vod_recovery()
            assert srv._vod_recovery_task is task
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            srv._start_vod_recovery()  # a finished task is replaced
            assert srv._vod_recovery_task is not task
            srv._vod_recovery_task.cancel()

    asyncio.run(go())


def test_cleanup_loop_starts_recovery_and_stop_cancels_it():
    import inspect
    server = _server_module()
    loop_src = inspect.getsource(server.PortalServer._data_cleanup_task)
    assert "_start_vod_recovery()" in loop_src, "the data cleanup loop does not retry recovery"
    stop_src = inspect.getsource(server.PortalServer.stop)
    assert "_cancel_vod_recovery()" in stop_src, "stop() does not cancel the recovery task"
    assert stop_src.index("_cancel_vod_recovery()") < stop_src.index("stop_all_recordings()")


# ---------------------------------------------------------------------------
# Stale chunks
# ---------------------------------------------------------------------------

def _recover(server, t, db, connect=None):
    calls = []

    async def default_connect(uid):
        calls.append(uid)
        return None, None, "connection refused"

    async def go():
        with mock.patch.object(server, "_connect_vod_sftp", connect or default_connect), \
                mock.patch.object(server, "db", db), \
                LogCapture() as cap:
            await server.recover_vod_staging(vs.list_session_dirs(t))
            return cap.text()

    return asyncio.run(go()), calls


def test_undeliverable_chunks_are_removed_after_14_days_with_a_count_and_bytes_line():
    server = _server_module()
    with tmp() as t:
        nosc_old = make_session(t, "1_nosidecar_old", chunks=("chunk_000.mkv", "chunk_001.mkv"), sidecar=False)
        nosc_new = make_session(t, "2_nosidecar_new", chunks=("chunk_000.mkv",), sidecar=False)
        user_gone = make_session(t, "3_user_gone", chunks=("chunk_000.mkv",))
        age(nosc_old, 15)
        age(nosc_new, 13)
        age(user_gone, 20)
        # the user id in make_session is 7
        log, calls = _recover(server, t, FakeDb(missing_users={7}))
        assert not nosc_old.exists() and not user_gone.exists(), "undeliverable old sessions were kept"
        assert (nosc_new / "chunk_000.mkv").exists(), "a 13 day old session was removed"
        assert "2 chunk(s), 36 bytes" in log, log  # "data-chunk_00N.mkv" is 18 bytes
        assert calls == [], "an undeliverable session must not try to connect"


def test_stale_log_line_names_count_and_bytes():
    server = _server_module()
    with tmp() as t:
        d = make_session(t, "1_x", chunks=("chunk_000.mkv", "chunk_001.mkv"), sidecar=False)
        size = sum(os.path.getsize(d / n) for n in ("chunk_000.mkv", "chunk_001.mkv"))
        age(d, 15)
        log, _ = _recover(server, t, FakeDb())
        assert f"2 chunk(s), {size} bytes" in log, log
        assert "removed 1_x" in log


def test_storage_gone_is_stale_but_unreachable_storage_is_not():
    server = _server_module()
    with tmp() as t:
        gone = make_session(t, "1_gone", chunks=("chunk_000.mkv",))
        age(gone, 30)
        log, calls = _recover(server, t, FakeDb(missing_storage={7}))
        assert not gone.exists() and "no VOD storage" in log, log
    with tmp() as t:
        down = make_session(t, "1_down", chunks=("chunk_000.mkv",))
        age(down, 30)
        log, calls = _recover(server, t, FakeDb())  # owner and storage exist, SFTP refuses
        assert calls == [7] and (down / "chunk_000.mkv").exists(), "chunks of a reachable owner were removed"
        assert vs.read_sidecar(str(down)) is not None
    with tmp() as t:
        locked = make_session(t, "1_locked", chunks=("chunk_000.mkv",))
        age(locked, 30)
        log, calls = _recover(server, t, FakeDb(raises=True))
        assert (locked / "chunk_000.mkv").exists(), "a database error must not delete chunks"


def test_age_is_measured_from_the_newest_chunk_not_the_folder():
    server = _server_module()
    with tmp() as t:
        d = make_session(t, "1_x", chunks=("chunk_000.mkv",), sidecar=False)
        age(d, 30)
        (d / "chunk_001.mkv").write_text("fresh")  # newest chunk is new
        os.utime(d, (0, 0))  # folder time says ancient
        log, _ = _recover(server, t, FakeDb())
        assert (d / "chunk_000.mkv").exists() and (d / "chunk_001.mkv").exists()


def test_stale_removal_deletes_only_chunks_and_record():
    with tmp() as t:
        d = make_session(t, "1_x", chunks=("chunk_000.mkv",))
        (d / "other.txt").write_text("not a chunk")
        sub = d / "sub"
        sub.mkdir()
        (sub / "keep").write_text("k")
        count, size = vs.remove_stale_session(str(d))
        assert count == 1 and size == len("data-chunk_000.mkv")
        assert (d / "other.txt").exists() and (sub / "keep").exists(), "stale removal recursed"
        assert not (d / "chunk_000.mkv").exists() and not (d / vs.SIDECAR_NAME).exists()


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
