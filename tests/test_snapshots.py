"""Tests for update snapshots. Run: venv/bin/python tests/test_snapshots.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""
import asyncio
import json
import os
import sqlite3
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import update_manager as um  # noqa: E402
import vod_staging  # noqa: E402

# The sandboxes live under /tmp, which a custom staging folder may not (see
# tests/test_vod_staging.py); these tests are about snapshots, not that rule.
vod_staging.TEMP_ROOTS = ()


def mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


class Sandbox:
    """Point update_manager at a throwaway project tree and stub its subprocess runner."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="snaptest_")
        self.root = Path(self._tmp.name) / "proj"
        self.root.mkdir()
        os.chmod(self.root, 0o777)  # hostile source mode
        self.calls = []
        self._saved = {}

    def __enter__(self):
        for name in ("PORTAL_DIR", "BACKUPS_DIR", "SNAPSHOTS_DIR", "HISTORY_FILE", "_run_cmd", "_get_portal_version"):
            self._saved[name] = getattr(um, name)
        um.PORTAL_DIR = self.root
        um.BACKUPS_DIR = self.root / "backups"
        um.SNAPSHOTS_DIR = um.BACKUPS_DIR / "snapshots"
        um.HISTORY_FILE = um.BACKUPS_DIR / "update_history.jsonl"

        async def fake_run(cmd, *a, **kw):
            self.calls.append(list(cmd))
            return 0, "", ""

        async def fake_version():
            return "0.0-test"

        um._run_cmd = fake_run
        um._get_portal_version = fake_version
        return self

    def __exit__(self, *exc):
        for name, val in self._saved.items():
            setattr(um, name, val)
        self._tmp.cleanup()


def populate(root: Path) -> None:
    (root / "server.py").write_text("print('x')\n")
    os.chmod(root / "server.py", 0o666)
    (root / ".env").write_text("JWT_SECRET=secret\n")
    (root / "sub").mkdir()
    os.chmod(root / "sub", 0o777)
    (root / "sub" / "a.txt").write_text("a")
    (root / "portal.db.backup").write_text("stray")
    (root / "venv").mkdir()
    (root / "venv" / "big").write_text("no")


def make_wal_db(path: Path) -> sqlite3.Connection:
    """Create a WAL database whose newest row exists only in the -wal file."""
    keeper = sqlite3.connect(path)
    keeper.execute("PRAGMA journal_mode=WAL")
    keeper.execute("PRAGMA wal_autocheckpoint=0")
    keeper.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    keeper.execute("INSERT INTO t (v) VALUES ('before')")
    keeper.commit()
    # A second connection writes and commits while the first keeps the db open.
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("INSERT INTO t (v) VALUES ('in-wal-only')")
    writer.commit()
    writer.close()
    return keeper


def test_snapshot_dir_mode_and_contents():
    with Sandbox() as sb:
        populate(sb.root)
        keeper = make_wal_db(sb.root / "portal.db")
        assert (sb.root / "portal.db-wal").stat().st_size > 0, "test setup: WAL must hold data"
        old_umask = os.umask(0)  # permissive umask must not matter
        try:
            meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "portal.db")))
        finally:
            os.umask(old_umask)
        snap = Path(meta["path"])
        assert mode(snap) == 0o700, oct(mode(snap))
        assert mode(um.BACKUPS_DIR) == 0o700 and mode(um.SNAPSHOTS_DIR) == 0o700
        # Nothing group/other writable anywhere inside
        for dp, dns, fns in os.walk(snap):
            for n in dns + fns:
                m = mode(os.path.join(dp, n))
                assert not m & 0o022, (n, oct(m))
        assert (snap / "server.py").exists() and (snap / "sub" / "a.txt").exists()
        assert not (snap / "venv").exists()
        assert not (snap / "portal.db.backup").exists()
        assert not (snap / "portal.db-wal").exists() and not (snap / "portal.db-shm").exists()

        # The snapshot DB is one consistent file containing the WAL-only row.
        db = sqlite3.connect(snap / "portal.db")
        rows = [r[0] for r in db.execute("SELECT v FROM t ORDER BY id")]
        assert rows == ["before", "in-wal-only"], rows
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        db.close()
        assert not (snap / "portal.db-wal").exists()
        assert mode(snap / "portal.db") == 0o600

        stored = json.loads((um.SNAPSHOTS_DIR / f"{meta['id']}.json").read_text())
        assert stored["db_integrity"] == "ok", stored
        assert stored["db_size_bytes"] == (snap / "portal.db").stat().st_size
        assert mode(um.SNAPSHOTS_DIR / f"{meta['id']}.json") == 0o600
        keeper.close()


def test_existing_loose_parent_dirs_are_tightened():
    with Sandbox() as sb:
        populate(sb.root)
        um.BACKUPS_DIR.mkdir()
        os.chmod(um.BACKUPS_DIR, 0o775)
        um.SNAPSHOTS_DIR.mkdir()
        os.chmod(um.SNAPSHOTS_DIR, 0o755)
        asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "missing.db")))
        assert mode(um.BACKUPS_DIR) == 0o700 and mode(um.SNAPSHOTS_DIR) == 0o700


def test_symlinked_backups_dir_is_not_chmodded():
    with Sandbox() as sb:
        elsewhere = sb.root.parent / "elsewhere"
        elsewhere.mkdir()
        os.chmod(elsewhere, 0o755)
        os.symlink(elsewhere, um.BACKUPS_DIR)
        um._ensure_private_dirs(snapshots=False)
        assert mode(elsewhere) == 0o755, oct(mode(elsewhere))


def test_existing_parent_modes_not_loosened():
    with Sandbox() as sb:
        populate(sb.root)
        um.BACKUPS_DIR.mkdir()
        os.chmod(um.BACKUPS_DIR, 0o700)
        um.SNAPSHOTS_DIR.mkdir()
        os.chmod(um.SNAPSHOTS_DIR, 0o700)
        asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "missing.db")))
        assert mode(um.BACKUPS_DIR) == 0o700 and mode(um.SNAPSHOTS_DIR) == 0o700


def test_backup_db_mode_and_free_space_refusal():
    import collections
    with Sandbox() as sb:
        populate(sb.root)
        keeper = make_wal_db(sb.root / "portal.db")
        outdir = sb.root / "private_out"
        outdir.mkdir()
        os.chmod(outdir, 0o700)
        dest, size, result = um.backup_database(str(outdir / "out.db"), db_path=str(sb.root / "portal.db"))
        assert mode(dest) == 0o600 and result == "ok"
        assert [p.name for p in outdir.iterdir()] == ["out.db"], "no temporary files may be left behind"
        db = sqlite3.connect(dest)
        assert db.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 2
        db.close()
        # existing output is never overwritten
        try:
            um.backup_database(str(dest), db_path=str(sb.root / "portal.db"))
            raise AssertionError("should refuse to overwrite")
        except RuntimeError:
            pass
        # less than twice the database size free: refuse and write nothing
        real = um.shutil.disk_usage
        Usage = collections.namedtuple("Usage", "total used free")
        um.shutil.disk_usage = lambda p: Usage(10, 10, 1)
        try:
            um.backup_database(str(outdir / "second.db"), db_path=str(sb.root / "portal.db"))
            raise AssertionError("should refuse on low disk space")
        except RuntimeError as e:
            assert "free disk space" in str(e), e
        finally:
            um.shutil.disk_usage = real
        assert [p.name for p in outdir.iterdir()] == ["out.db"]
        keeper.close()


def test_backup_db_destination_directory_rules():
    with Sandbox() as sb:
        populate(sb.root)
        db = str(sb.root / "portal.db")
        keeper = make_wal_db(sb.root / "portal.db")
        shared = sb.root / "shared"
        shared.mkdir()
        # group or other writable, no sticky bit: refused, nothing written
        for bad in (0o777, 0o770, 0o707):
            os.chmod(shared, bad)
            try:
                um.backup_database(str(shared / "x.db"), db_path=db)
                raise AssertionError(f"should refuse a {bad:04o} directory")
            except RuntimeError as e:
                assert "writable by group or other" in str(e), e
            assert list(shared.iterdir()) == []
        # sticky shared directory (like /tmp): accepted, and no temp dir is left
        os.chmod(shared, 0o1777)
        dest, size, result = um.backup_database(str(shared / "x.db"), db_path=db)
        assert result == "ok" and mode(dest) == 0o600
        assert [p.name for p in shared.iterdir()] == ["x.db"]
        keeper.close()


def test_backup_db_builds_in_private_temp_dir_and_never_overwrites():
    with Sandbox() as sb:
        populate(sb.root)
        db = str(sb.root / "portal.db")
        keeper = make_wal_db(sb.root / "portal.db")
        outdir = sb.root / "o"
        outdir.mkdir()
        os.chmod(outdir, 0o1777)
        real = um._sqlite_backup
        seen = {}

        def spy(src, dest):
            seen["dest"] = dest
            seen["parent_mode"] = mode(os.path.dirname(dest))
            # someone plants the destination while the copy is being built
            (outdir / "x.db").write_text("planted")
            return real(src, dest)

        um._sqlite_backup = spy
        try:
            try:
                um.backup_database(str(outdir / "x.db"), db_path=db)
                raise AssertionError("must not overwrite a file that appeared meanwhile")
            except RuntimeError as e:
                assert "overwrite" in str(e), e
        finally:
            um._sqlite_backup = real
        assert os.path.dirname(seen["dest"]) != str(outdir), "copy must not be built in the shared directory itself"
        assert seen["parent_mode"] == 0o700, oct(seen["parent_mode"])
        assert (outdir / "x.db").read_text() == "planted"
        assert [p.name for p in outdir.iterdir()] == ["x.db"], "temp dir must be removed"
        keeper.close()


def test_backup_db_refuses_symlink_at_destination():
    with Sandbox() as sb:
        populate(sb.root)
        db = str(sb.root / "portal.db")
        keeper = make_wal_db(sb.root / "portal.db")
        shared = sb.root / "sticky"
        shared.mkdir()
        os.chmod(shared, 0o1777)
        target = sb.root / "target"
        target.mkdir()
        os.chmod(target, 0o755)
        # dangling link, and a link to an existing file: both refused, nothing written
        (shared / "x.db").symlink_to(target / "planted.db")
        (target / "real.db").write_text("keep")
        (shared / "y.db").symlink_to(target / "real.db")
        for name in ("x.db", "y.db"):
            try:
                um.backup_database(str(shared / name), db_path=db)
                raise AssertionError("must refuse a symlink at the destination")
            except RuntimeError as e:
                assert "Refusing to overwrite" in str(e), e
        assert sorted(p.name for p in target.iterdir()) == ["real.db"]
        assert (target / "real.db").read_text() == "keep"
        assert sorted(p.name for p in shared.iterdir()) == ["x.db", "y.db"]
        # a symlinked directory component is still followed (the operator named it)
        link = sb.root / "dirlink"
        link.symlink_to(sb.root / "o2")
        (sb.root / "o2").mkdir()
        os.chmod(sb.root / "o2", 0o700)
        dest, size, result = um.backup_database(str(link / "ok.db"), db_path=db)
        assert result == "ok" and dest == (sb.root / "o2" / "ok.db").resolve()
        keeper.close()


def _rollback(sb, snap_id):
    job = {"id": "j", "log": []}
    asyncio.run(um._apply_rollback(job, snap_id))
    return job


def test_rollback_refuses_unsafe_snapshot():
    with Sandbox() as sb:
        populate(sb.root)
        meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
        snap = Path(meta["path"])
        before = sorted(p.name for p in sb.root.iterdir())

        # (a) snapshot directory writable by other
        os.chmod(snap, 0o707)
        sb.calls.clear()
        try:
            _rollback(sb, meta["id"])
            raise AssertionError("rollback should have refused (dir o+w)")
        except RuntimeError as e:
            assert "Refusing to roll back" in str(e), e
        os.chmod(snap, 0o700)

        # (b) a file inside it writable by group
        os.chmod(snap / "server.py", 0o664)
        try:
            _rollback(sb, meta["id"])
            raise AssertionError("rollback should have refused (file g+w)")
        except RuntimeError as e:
            assert "server.py" in str(e), e
        os.chmod(snap / "server.py", 0o644)

        # (c) a nested file
        os.chmod(snap / "sub" / "a.txt", 0o646)
        try:
            _rollback(sb, meta["id"])
            raise AssertionError("rollback should have refused (nested o+w)")
        except RuntimeError:
            pass
        os.chmod(snap / "sub" / "a.txt", 0o644)

        assert sorted(p.name for p in sb.root.iterdir()) == before, "refusal must change nothing"
        assert (sb.root / "server.py").read_text() == "print('x')\n"
        assert not sb.calls, f"no commands may run on refusal: {sb.calls}"
        # Only a stray extra snapshot must not have been created either
        assert len(list(um.SNAPSHOTS_DIR.glob("snap_*.json"))) == 1


def test_rollback_refuses_loose_or_foreign_backup_dirs():
    with Sandbox() as sb:
        populate(sb.root)
        meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
        before = sorted(p.name for p in sb.root.iterdir())
        for d, bad in ((um.SNAPSHOTS_DIR, 0o770), (um.SNAPSHOTS_DIR, 0o702),
                       (um.BACKUPS_DIR, 0o770), (um.BACKUPS_DIR, 0o707)):
            os.chmod(d, bad)
            try:
                _rollback(sb, meta["id"])
                raise AssertionError(f"rollback should have refused {d.name} mode {bad:04o}")
            except RuntimeError as e:
                assert "Refusing to roll back" in str(e) and d.name in str(e), e
            os.chmod(d, 0o700)
        assert sorted(p.name for p in sb.root.iterdir()) == before
        assert (sb.root / "server.py").read_text() == "print('x')\n"
        assert len(list(um.SNAPSHOTS_DIR.glob("snap_*.json"))) == 1, "refusal must not create a safety snapshot"
        # an owned, private layout is accepted by the guard
        um._check_snapshot_restorable(Path(meta["path"]), um._ROLLBACK_PRESERVE_DIRS | um._ROLLBACK_PRESERVE_FILES)
        # a symlinked backups directory is refused as well
        real = sb.root / "backups_real"
        os.rename(um.BACKUPS_DIR, real)
        os.symlink(real, um.BACKUPS_DIR)
        try:
            _rollback(sb, meta["id"])
            raise AssertionError("rollback should have refused a symlinked backups dir")
        except RuntimeError as e:
            assert "Refusing to roll back" in str(e), e


def test_rollback_rechecks_after_safety_snapshot():
    with Sandbox() as sb:
        populate(sb.root)
        meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
        snap = Path(meta["path"])
        before = sorted(p.name for p in sb.root.iterdir())
        real_create = um.create_snapshot

        async def loosen_then_create(*a, **kw):
            os.chmod(snap / "server.py", 0o666)  # tampering while the safety snapshot runs
            return await real_create(*a, **kw)

        um.create_snapshot = loosen_then_create
        try:
            try:
                _rollback(sb, meta["id"])
                raise AssertionError("rollback should have refused on the second check")
            except RuntimeError as e:
                assert "Refusing to roll back" in str(e), e
        finally:
            um.create_snapshot = real_create
        # only the safety snapshot directory was added; the project tree is untouched
        assert sorted(p.name for p in sb.root.iterdir()) == before
        assert (sb.root / "server.py").read_text() == "print('x')\n"
        assert not sb.calls or all("pip" not in " ".join(c) and "systemctl" not in " ".join(c) for c in sb.calls)


def test_history_creates_backups_dir_0700():
    with Sandbox():
        asyncio.run(um._record_history({"type": "x"}))
        assert mode(um.BACKUPS_DIR) == 0o700, oct(mode(um.BACKUPS_DIR))


def test_rollback_accepts_private_snapshot():
    with Sandbox() as sb:
        populate(sb.root)
        meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
        # Never run real pip / systemctl: the stub records them instead.
        (sb.root / "requirements.txt").write_text("")
        (sb.root / "server.py").write_text("changed\n")

        async def go():
            job = {"id": "j", "log": []}
            await um._apply_rollback(job, meta["id"])
            await asyncio.sleep(0)

        # asyncio.sleep(2) restart task is created; the stub swallows systemctl.
        async def runner():
            await go()
            await asyncio.sleep(2.2)

        asyncio.run(runner())
        assert (sb.root / "server.py").read_text() == "print('x')\n"


def _make_legacy_snapshot(sb, snap_id="snap_20260101_000000"):
    """Build a snapshot the way releases before the private-snapshot change did."""
    import shutil
    # production project tree: directories 0775, files 0664, nothing other-writable
    os.chmod(sb.root, 0o775)
    for dp, dns, fns in os.walk(sb.root):
        for n in dns:
            os.chmod(os.path.join(dp, n), 0o775)
        for n in fns:
            os.chmod(os.path.join(dp, n), 0o664)
    um.BACKUPS_DIR.mkdir(exist_ok=True)
    os.chmod(um.BACKUPS_DIR, 0o750)
    um.SNAPSHOTS_DIR.mkdir(exist_ok=True)
    os.chmod(um.SNAPSHOTS_DIR, 0o750)
    snap = um.SNAPSHOTS_DIR / snap_id
    shutil.copytree(str(sb.root), str(snap), ignore=shutil.ignore_patterns("venv", "backups"))
    assert mode(snap) == 0o775, oct(mode(snap))
    meta = {"id": snap_id, "reason": "old", "version": "0.0", "created_at": "x", "path": str(snap)}
    (um.SNAPSHOTS_DIR / f"{snap_id}.json").write_text(json.dumps(meta))
    return snap_id, snap


def _run_rollback_with_restart(sb, snap_id):
    (sb.root / "requirements.txt").write_text("")

    async def runner():
        await um._apply_rollback({"id": "j", "log": []}, snap_id)
        await asyncio.sleep(2.2)

    asyncio.run(runner())


def test_rollback_accepts_legacy_snapshot():
    with Sandbox() as sb:
        populate(sb.root)
        snap_id, snap = _make_legacy_snapshot(sb)
        (sb.root / "server.py").write_text("changed\n")
        _run_rollback_with_restart(sb, snap_id)
        assert (sb.root / "server.py").read_text() == "print('x')\n"
        assert mode(snap) == 0o700, oct(mode(snap))
        skipped = um._ROLLBACK_PRESERVE_DIRS | um._ROLLBACK_PRESERVE_FILES
        for item in snap.iterdir():
            if item.name in skipped:
                continue
            assert not mode(item) & 0o022, item.name
            for dp, dns, fns in os.walk(item):
                for n in dns + fns:
                    assert not mode(os.path.join(dp, n)) & 0o022, n


def test_rollback_still_refuses_legacy_snapshot_with_other_write():
    with Sandbox() as sb:
        populate(sb.root)
        snap_id, snap = _make_legacy_snapshot(sb)
        os.chmod(snap / "server.py", 0o666)
        try:
            _rollback(sb, snap_id)
            raise AssertionError("must refuse a legacy snapshot with an other-writable file")
        except RuntimeError as e:
            assert "Refusing to roll back" in str(e), e
        assert mode(snap / "server.py") == 0o666, "refusal must not change the snapshot"


def test_rollback_still_refuses_legacy_snapshot_in_loose_parent():
    with Sandbox() as sb:
        populate(sb.root)
        snap_id, snap = _make_legacy_snapshot(sb)
        os.chmod(um.SNAPSHOTS_DIR, 0o770)
        try:
            _rollback(sb, snap_id)
            raise AssertionError("must refuse when backups/snapshots is group-writable")
        except RuntimeError as e:
            assert "Refusing to roll back" in str(e), e


def test_rollback_refuses_legacy_snapshot_with_foreign_group_write():
    foreign = [g for g in os.getgroups() if g not in (os.getegid(), 0)]
    if not foreign:
        print("SKIP foreign group test: no supplementary group available")
        return
    with Sandbox() as sb:
        populate(sb.root)
        snap_id, snap = _make_legacy_snapshot(sb)
        os.chown(snap / "server.py", -1, foreign[0])
        os.chmod(snap / "server.py", 0o664)
        try:
            _rollback(sb, snap_id)
            raise AssertionError("must refuse group-writable files of a foreign group")
        except RuntimeError as e:
            assert "server.py" in str(e), e


def test_legacy_adoption_ignores_names_rollback_never_restores():
    with Sandbox() as sb:
        populate(sb.root)
        (sb.root / "data").mkdir()
        (sb.root / "data" / "x.txt").write_text("x")
        (sb.root / ".git").mkdir()
        (sb.root / ".git" / "HEAD").write_text("ref")
        snap_id, snap = _make_legacy_snapshot(sb)
        os.chmod(snap / "data" / "x.txt", 0o666)
        os.chmod(snap / ".git" / "HEAD", 0o666)
        os.chmod(snap / "portal.db.backup", 0o666)
        (sb.root / "server.py").write_text("changed\n")
        _run_rollback_with_restart(sb, snap_id)
        assert (sb.root / "server.py").read_text() == "print('x')\n"
        assert mode(snap) == 0o700
        # entries that rollback never restores are neither judged nor changed
        assert mode(snap / "data" / "x.txt") == 0o666
        assert mode(snap / ".git" / "HEAD") == 0o666
        assert mode(snap / "server.py") & 0o022 == 0


def test_new_snapshot_group_write_not_adopted():
    with Sandbox() as sb:
        populate(sb.root)
        meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
        snap = Path(meta["path"])
        os.chmod(snap / "server.py", 0o664)
        try:
            _rollback(sb, meta["id"])
            raise AssertionError("a current-format snapshot must never be loosened-and-adopted")
        except RuntimeError as e:
            assert "Refusing to roll back" in str(e), e
        assert mode(snap / "server.py") == 0o664


def test_same_second_clash_does_not_delete_existing_snapshot():
    with Sandbox() as sb:
        populate(sb.root)
        meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
        snap = Path(meta["path"])
        real_dt = um.datetime

        class Frozen(real_dt):
            @classmethod
            def now(cls, tz=None):
                return real_dt.strptime(meta["id"][5:], "%Y%m%d_%H%M%S")

        um.datetime = Frozen
        try:
            try:
                asyncio.run(um.create_snapshot("again", db_path=str(sb.root / "none.db")))
                raise AssertionError("same-id snapshot must fail")
            except RuntimeError:
                pass
        finally:
            um.datetime = real_dt
        assert (snap / "server.py").exists(), "existing snapshot must survive an id clash"


def test_failed_db_backup_leaves_no_snapshot_dir():
    with Sandbox() as sb:
        populate(sb.root)
        (sb.root / "bad.db").write_text("this is not a sqlite database" * 50)
        try:
            asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "bad.db")))
            raise AssertionError("snapshot should fail on an unreadable database")
        except RuntimeError as e:
            assert "back up the database" in str(e), e
        assert not list(um.SNAPSHOTS_DIR.glob("snap_*")), list(um.SNAPSHOTS_DIR.iterdir())


def test_failed_snapshot_cleanup_runs_off_the_event_loop():
    import threading
    for broken in ("copy", "db"):
        with Sandbox() as sb:
            populate(sb.root)
            (sb.root / "bad.db").write_text("this is not a sqlite database" * 50)
            seen = []
            real_rmtree = um.shutil.rmtree
            real_copy = um._strip_group_other_write

            def spy(path, *a, **kw):
                seen.append(threading.get_ident())
                return real_rmtree(path, *a, **kw)

            def boom(*a, **kw):
                raise OSError("simulated copy failure")

            um.shutil.rmtree = spy
            if broken == "copy":
                um._strip_group_other_write = boom
            main_ident = []

            async def go():
                main_ident.append(threading.get_ident())
                try:
                    await um.create_snapshot("test", db_path=str(sb.root / "bad.db"))
                    raise AssertionError("snapshot should fail")
                except RuntimeError:
                    pass

            try:
                asyncio.run(go())
            finally:
                um.shutil.rmtree = real_rmtree
                um._strip_group_other_write = real_copy
            assert seen, f"{broken}: failed snapshot was not cleaned up"
            assert all(t != main_ident[0] for t in seen), f"{broken}: rmtree ran on the event loop thread"
            assert not list(um.SNAPSHOTS_DIR.glob("snap_*")), broken


def test_snapshot_skips_vod_staging_and_rollback_keeps_it():
    from config import Config
    with Sandbox() as sb:
        populate(sb.root)
        (sb.root / "data" / "vod_tmp" / "1_2026-01-01_1").mkdir(parents=True)
        pending = sb.root / "data" / "vod_tmp" / "1_2026-01-01_1" / "chunk_000.mkv"
        pending.write_text("pending")
        (sb.root / "data" / "keep.txt").write_text("k")
        custom = sb.root / "elsewhere"
        custom.mkdir()
        (custom / "chunk_001.mkv").write_text("pending")
        vod_staging.ensure_private_dir(str(custom), adopt_nonempty=True)  # the portal marks its own folder
        saved = Config.VOD_TEMP_DIR
        Config.VOD_TEMP_DIR = str(custom)
        try:
            meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
            snap = Path(meta["path"])
            assert not (snap / "data" / "vod_tmp").exists(), "staging folder was copied into the snapshot"
            assert not (snap / "elsewhere").exists(), "a relocated staging folder was copied into the snapshot"
            assert (snap / "data" / "keep.txt").exists()
            # Rollback restores code only and leaves data/ (and the pending chunk) alone.
            (sb.root / "server.py").write_text("changed\n")
            _run_rollback_with_restart(sb, meta["id"])
        finally:
            Config.VOD_TEMP_DIR = saved
        assert (sb.root / "server.py").read_text() == "print('x')\n"
        assert pending.read_text() == "pending", "rollback removed a pending VOD chunk"
        # ... and so is a custom folder directly inside the project folder
        assert (custom / "chunk_001.mkv").read_text() == "pending", "rollback removed a custom staging folder"


def _staging_nested_setup(sb, marker: bool):
    """A project with code/ (restorable) and a staging folder code/vods inside it."""
    populate(sb.root)
    (sb.root / "code").mkdir()
    (sb.root / "code" / "mod.py").write_text("v1\n")
    nested = sb.root / "code" / "vods"
    nested.mkdir()
    (nested / "chunk_009.mkv").write_text("pending")
    if marker:
        vod_staging.ensure_private_dir(str(nested), adopt_nonempty=True)
    return nested


def test_rollback_keeps_a_custom_staging_folder_nested_in_a_code_folder():
    from config import Config
    with Sandbox() as sb:
        nested = _staging_nested_setup(sb, marker=True)
        saved = Config.VOD_TEMP_DIR
        Config.VOD_TEMP_DIR = str(nested)
        try:
            meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
            snap = Path(meta["path"])
            assert not (snap / "code" / "vods").exists(), "nested staging folder was copied into the snapshot"
            assert (snap / "code" / "mod.py").read_text() == "v1\n"
            (sb.root / "code" / "mod.py").write_text("v2\n")
            (sb.root / "code" / "extra.py").write_text("new\n")
            _run_rollback_with_restart(sb, meta["id"])
        finally:
            Config.VOD_TEMP_DIR = saved
        assert (nested / "chunk_009.mkv").read_text() == "pending", "rollback removed the nested staging folder"
        assert (sb.root / "code" / "mod.py").read_text() == "v1\n", "code next to the staging folder was not restored"
        assert not (sb.root / "code" / "extra.py").exists(), "rollback left a file that is not in the snapshot"


def test_unmarked_configured_folder_is_not_treated_as_staging_by_snapshot_or_rollback():
    # A VOD_TEMP_DIR the portal refused (not its own folder) must not be frozen:
    # the update process reads the raw setting and has no way to know it was refused.
    from config import Config
    with Sandbox() as sb:
        populate(sb.root)
        code = sb.root / "tools"
        code.mkdir()
        (code / "t.py").write_text("v1\n")
        saved = Config.VOD_TEMP_DIR
        Config.VOD_TEMP_DIR = str(code)
        try:
            meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
            assert (Path(meta["path"]) / "tools" / "t.py").exists(), "an unmarked folder was left out of the snapshot"
            (code / "t.py").write_text("v2\n")
            _run_rollback_with_restart(sb, meta["id"])
        finally:
            Config.VOD_TEMP_DIR = saved
        assert (sb.root / "tools" / "t.py").read_text() == "v1\n", "an unmarked folder was frozen against rollback"


def _populate_recordings(folder: Path) -> Path:
    folder.mkdir(parents=True)
    cast = folder / "rec_1_1_20260101_000000_ab.cast"
    cast.write_text("recorded")
    return cast


def test_snapshot_skips_recordings_and_rollback_keeps_them():
    from config import Config
    with Sandbox() as sb:
        populate(sb.root)
        default_cast = _populate_recordings(sb.root / "recordings")
        custom_cast = _populate_recordings(sb.root / "privatedata" / "rec")  # nested custom folder
        (sb.root / "privatedata" / "code.py").write_text("v1\n")
        saved = Config.RECORDINGS_DIR
        try:
            for configured, cast in ((str(sb.root / "recordings"), default_cast),
                                     (str(sb.root / "privatedata" / "rec"), custom_cast)):
                Config.RECORDINGS_DIR = configured
                meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
                snap = Path(meta["path"])
                assert not (snap / os.path.relpath(configured, sb.root)).exists(), \
                    f"the recordings folder was copied into the snapshot ({configured})"
                (sb.root / "server.py").write_text("changed\n")
                cast.write_text("recorded after the snapshot")
                _run_rollback_with_restart(sb, meta["id"])
                assert (sb.root / "server.py").read_text() == "print('x')\n"
                assert cast.read_text() == "recorded after the snapshot", f"rollback replaced recordings in {configured}"
                cast.write_text("recorded")
        finally:
            Config.RECORDINGS_DIR = saved
        assert (sb.root / "privatedata" / "code.py").read_text() == "v1\n"


def test_unsafe_configured_recordings_folder_is_not_frozen_against_rollback():
    from config import Config
    with Sandbox() as sb:
        populate(sb.root)
        code = sb.root / "tools"
        code.mkdir()
        (code / "t.py").write_text("v1\n")  # holds code, so the portal itself refuses it as a recordings folder
        saved = Config.RECORDINGS_DIR
        Config.RECORDINGS_DIR = str(code)
        try:
            meta = asyncio.run(um.create_snapshot("test", db_path=str(sb.root / "none.db")))
            assert (Path(meta["path"]) / "tools" / "t.py").exists()
            (code / "t.py").write_text("v2\n")
            _run_rollback_with_restart(sb, meta["id"])
        finally:
            Config.RECORDINGS_DIR = saved
        assert (sb.root / "tools" / "t.py").read_text() == "v1\n"


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
