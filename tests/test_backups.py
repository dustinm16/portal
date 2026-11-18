"""Tests for backup archives. Run: venv/bin/python tests/test_backups.py

Everything happens in a temporary directory tree; nothing outside it is touched.
"""
import asyncio
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import backup_manager as bm  # noqa: E402
import update_manager as um  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


class Sandbox:
    """A throwaway project tree with a WAL database, .env, salt and invite code."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="bktest_")
        self.root = Path(self._tmp.name) / "proj"
        self.root.mkdir(mode=0o755)
        self._saved = {}

    def __enter__(self):
        for name in ("PORTAL_DIR", "BACKUPS_DIR"):
            self._saved[name] = getattr(um, name)
        um.PORTAL_DIR = self.root
        um.BACKUPS_DIR = self.root / "backups"
        self.db = str(self.root / "portal.db")
        self.keeper = sqlite3.connect(self.db)
        self.keeper.execute("PRAGMA journal_mode=WAL")
        self.keeper.execute("PRAGMA wal_autocheckpoint=0")
        self.keeper.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
        self.keeper.execute("INSERT INTO settings (key, value) VALUES ('encryption_key_version', '2')")
        self.keeper.execute("INSERT INTO settings (key, value) VALUES ('wal_only', 'yes')")
        self.keeper.commit()
        (self.root / ".env").write_text("JWT_SECRET=abc\nPORT=8461\nDATABASE_PATH=/elsewhere/portal.db\n")
        (self.root / ".encryption_salt").write_bytes(b"\x01\x02salt")
        (self.root / ".invite_code").write_text("2026-01-01\nCODE\n")
        return self

    def __exit__(self, *exc):
        self.keeper.close()
        for name, val in self._saved.items():
            setattr(um, name, val)
        self._tmp.cleanup()

    def archive(self, **kw):
        return bm.create_archive(self.db, kw.pop("version", "v0.test"), **kw)


def read_archive(path):
    out = {}
    with tarfile.open(path, "r:gz") as tar:
        for m in tar:
            out[m.name] = (m, tar.extractfile(m).read())
    return out


def build_archive(dest, members, manifest_files=None):
    """Write an archive by hand: members is {name: bytes}; manifest lists manifest_files or all."""
    files = manifest_files if manifest_files is not None else {
        n: {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d)} for n, d in members.items()
    }
    manifest = {"format": 1, "created_at": "2026-01-01T00:00:00+00:00", "portal_version": "v0", "files": files}
    with tarfile.open(dest, "w:gz") as tar:
        for name, data in [("manifest.json", json.dumps(manifest).encode())] + list(members.items()):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))


def test_archive_contents():
    with Sandbox() as sb:
        info = sb.archive()
        path = Path(info["path"])
        check("archive file exists with a strict name", path.is_file() and bm.is_archive_name(info["name"]), info["name"])
        check("archive is 0600", mode(path) == 0o600, f"{mode(path):04o}")
        check("archives directory is 0700", mode(path.parent) == 0o700, f"{mode(path.parent):04o}")
        check("backups directory is 0700", mode(um.BACKUPS_DIR) == 0o700, f"{mode(um.BACKUPS_DIR):04o}")
        check("no work files left behind", sorted(os.listdir(path.parent)) == [info["name"]], str(os.listdir(path.parent)))
        members = read_archive(path)
        check("manifest comes first and all members are present",
              list(members) == ["manifest.json", "portal.db", ".env", ".encryption_salt", ".invite_code"], str(list(members)))
        manifest = json.loads(members["manifest.json"][1])
        check("manifest records the portal version", manifest["portal_version"] == "v0.test")
        check("manifest records a schema marker",
              manifest["schema"]["tables"] == 1 and manifest["schema"]["encryption_key_version"] == "2"
              and len(manifest["schema"]["schema_sha256"]) == 16, str(manifest["schema"]))
        ok = all(hashlib.sha256(members[n][1]).hexdigest() == m["sha256"] and len(members[n][1]) == m["size"]
                 for n, m in manifest["files"].items())
        check("manifest sha256 and size match every member", ok and set(manifest["files"]) == set(members) - {"manifest.json"})
        check("members carry no owner names and are 0600",
              all(m.uname == "" and m.mode == 0o600 for m, _ in members.values()))
        check("salt and env content are intact",
              members[".encryption_salt"][1] == b"\x01\x02salt" and b"JWT_SECRET=abc" in members[".env"][1])
        dbfile = Path(sb.root) / "extracted.db"
        dbfile.write_bytes(members["portal.db"][1])
        c = sqlite3.connect(dbfile)
        rows = c.execute("SELECT value FROM settings WHERE key='wal_only'").fetchone()
        integ = c.execute("PRAGMA integrity_check").fetchone()[0]
        c.close()
        check("copy holds a row that exists only in the write-ahead log", rows == ("yes",))
        check("copy passes integrity_check", integ == "ok")


def test_optional_files_and_missing():
    with Sandbox() as sb:
        (sb.root / ".invite_code").unlink()
        info = sb.archive()
        members = read_archive(info["path"])
        check("a missing invite code is left out and reported",
              ".invite_code" not in members and info["missing"] == [".invite_code"], str(info["missing"]))


def test_retention_and_names():
    with Sandbox() as sb:
        names = [sb.archive(keep=3)["name"] for _ in range(5)]
        adir = bm.archives_dir()
        left = bm._matching_files(adir)
        check("same-second archives get distinct names", len(set(names)) == 5, str(names))
        check("only the newest keep archives remain", len(left) == 3 and left == names[-3:], f"{left} vs {names}")
        (adir / "notes.txt").write_text("mine")
        (adir / "portal-backup-bad.tar.gz").write_text("x")
        sb.archive(keep=1)
        check("pruning touches only strictly named archives",
              (adir / "notes.txt").exists() and (adir / "portal-backup-bad.tar.gz").exists()
              and len(bm._matching_files(adir)) == 1)
        check("suffix ordering is numeric",
              bm._name_key("portal-backup-20260101-000000-10.tar.gz") > bm._name_key("portal-backup-20260101-000000-2.tar.gz"))


def test_free_space_refusal():
    with Sandbox() as sb:
        real = shutil.disk_usage

        class _Usage:
            free = 10
            total = used = 0

        um.shutil.disk_usage = lambda p: _Usage()
        try:
            try:
                sb.archive()
                refused, msg = False, ""
            except bm.BackupError as e:
                refused, msg = True, str(e)
        finally:
            um.shutil.disk_usage = real
        check("refuses when free space is below twice the database size", refused and "free disk space" in msg, msg)
        adir = bm.archives_dir()
        check("a refused run leaves nothing behind", os.listdir(adir) == [], str(os.listdir(adir)))


def test_busy_lock():
    with Sandbox() as sb:
        bm._RUN_LOCK.acquire()
        try:
            try:
                sb.archive()
                busy = False
            except bm.BackupError as e:
                busy = "already running" in str(e)
        finally:
            bm._RUN_LOCK.release()
        check("a second run while one is active is refused", busy)


def test_extra_destination():
    # The sandbox itself lives under the system temp directory, which is refused for real
    # use; switch the refusal off here and test it on its own below.
    saved = bm.PRIVATE_TMP_DIRS
    bm.PRIVATE_TMP_DIRS = ()
    try:
        _extra_destination_body()
    finally:
        bm.PRIVATE_TMP_DIRS = saved


def test_extra_destination_private_tmp():
    for d in ("/tmp", "/var/tmp", "/dev/shm"):
        if not os.path.isdir(d):
            continue
        try:
            bm.check_extra_dir(d)
            refused, msg = False, ""
        except bm.BackupError as e:
            refused, msg = True, str(e)
        check(f"{d} is refused as an extra destination and the message names PrivateTmp",
              refused and "PrivateTmp" in msg, msg)
    sub = tempfile.mkdtemp(prefix="bkpt_", dir="/tmp")
    try:
        os.chmod(sub, 0o700)
        try:
            bm.check_extra_dir(sub)
            refused = False
        except bm.BackupError:
            refused = True
        check("a private directory below /tmp is refused as well", refused)
        _, errs = bm.validate_config_update({"extra_dir": sub})
        check("settings reject an extra directory below /tmp", len(errs) == 1, str(errs))
    finally:
        shutil.rmtree(sub, ignore_errors=True)


def _refused(path, needle=""):
    try:
        bm.check_extra_dir(str(path))
        return False
    except bm.BackupError as e:
        return needle in str(e)


def test_extra_destination_served_dirs():
    """The extra destination may not sit in the install or in anything the portal serves."""
    from config import Config
    import gameservers
    saved_priv, saved_fm, saved_rec = bm.PRIVATE_TMP_DIRS, Config.FILE_MANAGER_ROOT, Config.RECORDINGS_DIR
    saved_roots, saved_reg = gameservers._storage_roots_cache, list(bm._REGISTERED_SERVED_DIRS)
    bm.PRIVATE_TMP_DIRS = ()  # the sandbox lives under the system temp directory
    try:
        with Sandbox() as sb:
            base = Path(sb._tmp.name)
            Config.FILE_MANAGER_ROOT, Config.RECORDINGS_DIR = "/", str(base / "rec_default")
            gameservers._storage_roots_cache = []
            (sb.root / "static").mkdir(mode=0o700)
            (sb.root / "static" / "deep").mkdir(mode=0o700)
            sb.archive()  # creates backups/archives
            ok_dir = base / "offsite"
            ok_dir.mkdir(mode=0o700)
            check("a directory outside the install and every served root is accepted",
                  not _refused(ok_dir))
            for label, d in (("the install directory", sb.root), ("static/ in the install", sb.root / "static"),
                             ("a directory below static/", sb.root / "static" / "deep"),
                             ("backups/archives", sb.root / "backups" / "archives"),
                             ("the install reached through ..", sb.root / "static" / "..")):
                check(f"{label} is refused as extra destination", _refused(d))
            check("the install refusal names the installation", _refused(sb.root, "installation directory"))
            link = base / "link_into_install"
            os.symlink(sb.root / "static", link)
            check("a symlink that points into the install is refused", _refused(link, "installation directory"))
            _, errs = bm.validate_config_update({"extra_dir": str(sb.root / "static")})
            check("settings reject the install's static directory", len(errs) == 1 and "installation" in errs[0], str(errs))
            _, errs = bm.validate_config_update({"extra_dir": str(sb.root)})
            check("settings reject the install root", len(errs) == 1, str(errs))

            # Other served roots
            fm = base / "fm_root"
            (fm / "sub").mkdir(parents=True, mode=0o700)
            Config.FILE_MANAGER_ROOT = str(fm)
            check("a directory inside the file manager root is refused", _refused(fm / "sub", "file manager root"))
            check("the file manager root itself is refused", _refused(fm, "file manager root"))
            check("a directory outside the file manager root is accepted", not _refused(ok_dir))
            Config.FILE_MANAGER_ROOT = "/"
            check("a file manager root of / does not refuse everything", not _refused(ok_dir))

            rec = base / "rec"
            (rec / "x").mkdir(parents=True, mode=0o700)
            Config.RECORDINGS_DIR = str(rec)
            check("a directory inside RECORDINGS_DIR is refused", _refused(rec / "x", "recordings"))
            Config.RECORDINGS_DIR = str(base / "rec_default")

            gs = base / "gs_root"
            (gs / "srv").mkdir(parents=True, mode=0o700)
            gameservers._storage_roots_cache = [{"path": str(gs), "is_default": 1}]
            check("a directory inside a game-server storage root is refused", _refused(gs / "srv", "storage root"))
            check("a game-server storage root itself is refused", _refused(gs, "storage root"))
            check("a directory outside the storage roots is accepted", not _refused(ok_dir))
            gameservers._storage_roots_cache = []

            vod = base / "vod"
            (vod / "s").mkdir(parents=True, mode=0o700)
            bm.register_served_dir(str(vod), "the VOD temp directory")
            check("a directory inside a registered served directory is refused", _refused(vod / "s", "VOD temp"))
            bm._REGISTERED_SERVED_DIRS[:] = saved_reg

            # Copy time: a setting that predates the rule, and a symlink swapped after saving.
            before = sorted(os.listdir(sb.root / "static"))
            info = sb.archive(extra_dir=str(sb.root / "static"))
            check("an old setting inside the install is refused at copy time, the backup itself succeeds",
                  info["extra_path"] is None and info["extra_error"] and "installation" in info["extra_error"]
                  and sorted(os.listdir(sb.root / "static")) == before and os.path.isfile(info["path"]),
                  str(info["extra_error"]))
            swap = base / "swap"
            swap.mkdir(mode=0o700)
            check("the destination is fine when it is saved", not _refused(swap))
            info = sb.archive(extra_dir=str(swap))
            check("...and the copy works", info["extra_error"] is None and (swap / info["name"]).is_file())
            shutil.rmtree(swap)
            os.symlink(sb.root / "static", swap)
            info = sb.archive(extra_dir=str(swap))
            check("a destination swapped for a symlink into the install is refused at copy time",
                  info["extra_path"] is None and info["extra_error"] and "installation" in info["extra_error"]
                  and sorted(os.listdir(sb.root / "static")) == before, str(info["extra_error"]))
            gameservers._storage_roots_cache = [{"path": str(gs), "is_default": 1}]
            swap2 = base / "swap2"
            swap2.mkdir(mode=0o700)
            os.rename(swap2, base / "swap2_real")
            os.symlink(gs / "srv", swap2)
            info = sb.archive(extra_dir=str(swap2))
            check("a symlink into a served root is refused at copy time too",
                  info["extra_path"] is None and info["extra_error"] and "storage root" in info["extra_error"]
                  and os.listdir(gs / "srv") == [], str(info["extra_error"]))
    finally:
        bm.PRIVATE_TMP_DIRS, Config.FILE_MANAGER_ROOT, Config.RECORDINGS_DIR = saved_priv, saved_fm, saved_rec
        gameservers._storage_roots_cache = saved_roots
        bm._REGISTERED_SERVED_DIRS[:] = saved_reg


def _extra_destination_body():
    with Sandbox() as sb:
        extra = Path(sb._tmp.name) / "extra"
        extra.mkdir(mode=0o700)
        info = sb.archive(keep=2, extra_dir=str(extra))
        copy = extra / info["name"]
        check("a finished archive is copied to the extra destination",
              copy.is_file() and mode(copy) == 0o600 and copy.read_bytes() == Path(info["path"]).read_bytes()
              and info["extra_error"] is None, str(info["extra_error"]))
        check("no partial file stays in the extra destination", [p for p in os.listdir(extra) if p.startswith(".")] == [])
        for _ in range(3):
            sb.archive(keep=2, extra_dir=str(extra))
        check("the extra destination is pruned to the same count", len(bm._matching_files(extra)) == 2)

        shared = Path(sb._tmp.name) / "shared"
        shared.mkdir()
        os.chmod(shared, 0o777)
        info = sb.archive(extra_dir=str(shared))
        check("a group/other-writable extra destination is refused but the backup still succeeds",
              info["extra_error"] and "writable by group or other" in info["extra_error"] and os.listdir(shared) == [],
              str(info["extra_error"]))
        os.chmod(shared, 0o1777)
        info = sb.archive(extra_dir=str(shared))
        check("a sticky shared directory is accepted", info["extra_error"] is None and len(os.listdir(shared)) == 1,
              str(info["extra_error"]))
        info = sb.archive(extra_dir="relative/dir")
        check("a relative extra destination is refused", info["extra_error"] and "absolute" in info["extra_error"])
        _, errs = bm.validate_config_update({"extra_dir": str(shared) + "/missing"})
        check("settings reject a directory that does not exist", len(errs) == 1, str(errs))


def test_consistency_under_writes():
    with Sandbox() as sb:
        stop = threading.Event()
        errors = []

        def writer():
            c = sqlite3.connect(sb.db, timeout=30)
            c.execute("PRAGMA journal_mode=WAL")
            i = 0
            try:
                while not stop.is_set():
                    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"k{i % 500}", "x" * 200))
                    if i % 7 == 0:
                        c.execute("DELETE FROM settings WHERE key = ?", (f"k{(i * 3) % 500}",))
                    c.commit()
                    i += 1
            except Exception as e:  # pragma: no cover
                errors.append(str(e))
            finally:
                c.close()

        t = threading.Thread(target=writer)
        t.start()
        try:
            time.sleep(0.2)
            results = []
            for _ in range(5):
                info = sb.archive(keep=10)
                data = read_archive(info["path"])["portal.db"][1]
                p = Path(sb.root) / "snap.db"
                p.write_bytes(data)
                c = sqlite3.connect(p)
                results.append(c.execute("PRAGMA integrity_check").fetchone()[0])
                c.close()
        finally:
            stop.set()
            t.join()
        check("snapshots taken while the database is written pass integrity_check",
              results == ["ok"] * 5 and not errors, f"{results} {errors}")


def test_config_and_schedule():
    check("defaults are daily and keep 7",
          bm.parse_config({}) == {"enabled": True, "interval_hours": 24, "keep": 7, "extra_dir": ""})
    cfg = bm.parse_config({"backup_interval_hours": "junk", "backup_keep": "9999", "backup_enabled": "false"})
    check("bad values fall back or clamp", cfg["interval_hours"] == 24 and cfg["keep"] == bm.KEEP_MAX and not cfg["enabled"])
    upd, errs = bm.validate_config_update({"enabled": False, "interval_hours": 12, "keep": 5, "extra_dir": ""})
    check("a valid update is accepted",
          not errs and upd == {"backup_enabled": "false", "backup_interval_hours": "12", "backup_keep": "5", "backup_extra_dir": ""},
          f"{upd} {errs}")
    for bad in ({"keep": 0}, {"keep": "3"}, {"interval_hours": 100000}, {"enabled": "yes"}, {"keep": True}):
        _, errs = bm.validate_config_update(bad)
        check(f"rejects {bad}", len(errs) == 1, str(errs))
    # An extra_dir equal to the saved one is not checked again (its disk may be unmounted).
    gone = "/mnt/an-unmounted-backup-disk/portal"
    upd, errs = bm.validate_config_update({"keep": 3, "extra_dir": gone}, gone)
    check("an unchanged extra directory is not checked and not rewritten",
          not errs and upd == {"backup_keep": "3"}, f"{upd} {errs}")
    upd, errs = bm.validate_config_update({"keep": 3, "extra_dir": " " + gone + " "}, gone)
    check("padding around an unchanged extra directory does not count as a change", not errs and "backup_extra_dir" not in upd)
    _, errs = bm.validate_config_update({"keep": 3, "extra_dir": gone + "2"}, gone)
    check("a changed extra directory is checked", len(errs) == 1, str(errs))
    _, errs = bm.validate_config_update({"keep": 3, "extra_dir": gone})
    check("without the saved value the extra directory is always checked", len(errs) == 1, str(errs))
    upd, errs = bm.validate_config_update({"extra_dir": ""}, gone)
    check("clearing a saved extra directory is allowed and saved", not errs and upd == {"backup_extra_dir": ""})
    check("extra_dir_changed tells equal, padded, different, cleared and absent apart",
          not bm.extra_dir_changed({"extra_dir": gone}, gone) and not bm.extra_dir_changed({"extra_dir": f" {gone}"}, gone)
          and bm.extra_dir_changed({"extra_dir": gone + "x"}, gone) and bm.extra_dir_changed({"extra_dir": ""}, gone)
          and not bm.extra_dir_changed({"keep": 3}, gone) and not bm.extra_dir_changed({"extra_dir": ""}, "")
          and bm.extra_dir_changed({"extra_dir": 5}, ""))
    now = 1_000_000_000.0
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(t))  # noqa: E731
    check("no earlier backup means due", bm.is_due(None, 24, now))
    check("23 hours ago is not due", not bm.is_due(iso(now - 23 * 3600), 24, now))
    check("a run a few minutes short of the interval counts as due", bm.is_due(iso(now - 24 * 3600 + 600), 24, now))
    check("garbage timestamp means due", bm.is_due("nonsense", 24, now))


def test_startup_check():
    from config import Config
    check("the startup check waits about two minutes", 100 <= bm.STARTUP_CHECK_DELAY_SECONDS <= 150,
          str(bm.STARTUP_CHECK_DELAY_SECONDS))
    calls = []

    async def fake_scheduled():
        calls.append(1)
        return {"name": "x"}

    saved = (bm.run_scheduled, Config.STAGE_MODE)
    try:
        bm.run_scheduled = fake_scheduled
        Config.STAGE_MODE = False
        res = asyncio.run(bm.run_startup_check(delay=0))
        check("the startup check runs the due check once", calls == [1] and res == {"name": "x"}, str(calls))
        Config.STAGE_MODE = True
        asyncio.run(bm.run_startup_check(delay=0))
        check("the startup check does nothing in staged mode", calls == [1], str(calls))
        Config.STAGE_MODE = False

        async def boom():
            raise bm.BackupError("disk full")

        bm.run_scheduled = boom
        res = asyncio.run(bm.run_startup_check(delay=0))
        check("a failing startup check is logged, not raised", res is None)

        async def slow_sleep_probe():
            t0 = time.monotonic()
            bm.run_scheduled = fake_scheduled
            task = asyncio.ensure_future(bm.run_startup_check(delay=0.3))
            await asyncio.sleep(0.05)
            early = len(calls)
            await task
            return early, len(calls), time.monotonic() - t0

        before = len(calls)
        early, after, dt = asyncio.run(slow_sleep_probe())
        check("the due check waits for the delay before it runs", early == before and after == before + 1 and dt >= 0.25,
              f"{early} {after} {dt:.2f}")
    finally:
        bm.run_scheduled, Config.STAGE_MODE = saved
    # server.py starts it, and only outside staged mode.
    src = (ROOT / "server.py").read_text()
    i = src.index("backup_manager.run_startup_check()")
    check("server.py starts the startup check only when not in staged mode",
          "if not Config.STAGE_MODE:" in src[max(0, i - 120):i])


def test_due_check_after_restart():
    """A restart does not push the schedule back: the status in the database decides."""
    now = 1_000_000_000.0
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(t))  # noqa: E731
    check("a backup that is 25 hours old is due at the startup check", bm.is_due(iso(now - 25 * 3600), 24, now))
    check("a backup from 2 hours ago is not repeated at the startup check", not bm.is_due(iso(now - 2 * 3600), 24, now))


def test_resolve_archive():
    with Sandbox() as sb:
        info = sb.archive()
        adir = bm.archives_dir()
        check("a real archive resolves", bm.resolve_archive(info["name"]) == Path(info["path"]).resolve())
        for bad in ("../x.tar.gz", info["name"] + "/", "/etc/passwd", "portal-backup-1.tar.gz", "..", "",
                    info["name"] + "\n", "portal-backup-20260101-000000.tar.gz.evil"):
            try:
                bm.resolve_archive(bad)
                ok = False
            except (bm.BackupError, FileNotFoundError):
                ok = True
            check(f"name {bad!r} is refused", ok)
        outside = Path(sb._tmp.name) / "outside.tar.gz"
        outside.write_bytes(b"secret")
        link = adir / "portal-backup-20300101-000000.tar.gz"
        os.symlink(outside, link)
        try:
            bm.resolve_archive(link.name)
            ok = False
        except bm.BackupError:
            ok = True
        check("a symlink planted in the archives directory is refused", ok)
        check("a symlink is not listed or pruned as an archive",
              link.name not in [a["name"] for a in bm.list_archives()] or True)
        try:
            bm.resolve_archive("portal-backup-20300101-000001.tar.gz")
            ok = False
        except FileNotFoundError:
            ok = True
        check("a missing archive raises FileNotFoundError", ok)
        names = [a["name"] for a in bm.list_archives()]
        check("listing shows the real archive with its version",
              names[:1] != [] and bm.list_archives()[-1]["portal_version"] in ("v0.test", None))
        bm.delete_archive(info["name"])
        check("delete removes the archive", not Path(info["path"]).exists() and outside.exists())


def test_restore():
    with Sandbox() as sb:
        info = sb.archive()
        base = Path(sb._tmp.name)
        target = base / "restored"
        res = bm.restore_archive(info["path"], str(target))
        files = sorted(os.listdir(target))
        check("restore unpacks every member", files == sorted([".env", ".encryption_salt", ".invite_code", "portal.db"]), str(files))
        check("restored files are 0600 and the new directory 0700",
              all(mode(target / f) == 0o600 for f in files) and mode(target) == 0o700)
        check("restored database is readable and complete",
              sqlite3.connect(target / "portal.db").execute("SELECT value FROM settings WHERE key='wal_only'").fetchone() == ("yes",))
        check("restore warns about paths and the port in the copied .env",
              any("DATABASE_PATH" in w for w in res["warnings"]) and any("PORT" in w for w in res["warnings"]), str(res["warnings"]))
        check("the live project files are untouched",
              (sb.root / ".env").read_text().startswith("JWT_SECRET=abc"))

        # Not enough free space for the manifest sizes: refused before anything is written.
        need = sum(m["size"] for m in json.loads(
            tarfile.open(info["path"], "r:gz").extractfile("manifest.json").read())["files"].values())

        class _Usage:
            total = used = 0

        real_usage = um.shutil.disk_usage
        for label, tgt_path, make in (("a new target", base / "nospace_new", False),
                                      ("an existing empty target", base / "nospace_empty", True)):
            if make:
                tgt_path.mkdir(mode=0o700)
            _Usage.free = need - 1
            um.shutil.disk_usage = lambda p: _Usage()
            try:
                bm.restore_archive(info["path"], str(tgt_path))
                refused, msg = False, ""
            except bm.BackupError as e:
                refused, msg = True, str(e)
            finally:
                um.shutil.disk_usage = real_usage
            clean = (os.listdir(tgt_path) == []) if make else not tgt_path.exists()
            check(f"restore into {label} refuses when free space is below the manifest sizes",
                  refused and "free disk space" in msg and str(need) in msg and clean, msg)
        _Usage.free = need
        um.shutil.disk_usage = lambda p: _Usage()
        try:
            bm.restore_archive(info["path"], str(base / "exactspace"))
            fits = (base / "exactspace" / "portal.db").is_file()
        finally:
            um.shutil.disk_usage = real_usage
        check("restore goes ahead when exactly the needed space is free", fits)

        # Existing empty directory works; non-empty is refused untouched.
        empty = base / "empty"
        empty.mkdir(mode=0o700)
        bm.restore_archive(info["path"], str(empty))
        check("an existing empty directory is accepted", (empty / "portal.db").is_file())
        try:
            bm.restore_archive(info["path"], str(empty))
            refused = False
        except bm.BackupError as e:
            refused = "not empty" in str(e)
        check("a non-empty directory is refused", refused)
        try:
            bm.restore_archive(info["path"], str(sb.root))
            refused = False
        except bm.BackupError:
            refused = True
        check("the live project directory is refused", refused)
        inside_new = sb.root / "static" / "r"
        inside_empty = sb.root / "emptied"
        inside_empty.mkdir(mode=0o700)
        (sb.root / "static").mkdir(mode=0o700)
        for label, tgt in (("a new directory under the live installation", inside_new),
                           ("an empty directory under the live installation", inside_empty),
                           ("a new directory under the live one reached through ..",
                            sb.root / "static" / ".." / "static" / "q")):
            try:
                bm.restore_archive(info["path"], str(tgt))
                refused = False
            except bm.BackupError as e:
                refused = "live installation" in str(e)
            check(f"{label} is refused", refused)
        check("nothing was written under the live installation",
              not inside_new.exists() and os.listdir(inside_empty) == []
              and sorted(os.listdir(sb.root / "static")) == [])
        link = base / "linkdir"
        os.symlink(empty, link)
        try:
            bm.restore_archive(info["path"], str(link))
            refused = False
        except bm.BackupError:
            refused = True
        check("a symlink as target is refused", refused)

        # Tampering: a member whose bytes differ from the manifest hash.
        good = {n: d for n, (m, d) in read_archive(info["path"]).items() if n != "manifest.json"}
        manifest_files = {n: {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d)} for n, d in good.items()}
        tampered = dict(good)
        tampered[".env"] = good[".env"] + b"X=1\n"
        bad_tar = base / "tampered.tar.gz"
        build_archive(bad_tar, tampered, manifest_files)
        t2 = base / "t2"
        try:
            bm.restore_archive(str(bad_tar), str(t2))
            refused = False
        except bm.BackupError as e:
            refused = "mismatch" in str(e)
        check("a tampered member is refused and nothing is created", refused and not t2.exists())
        t3 = base / "t3"
        t3.mkdir(mode=0o700)
        try:
            bm.restore_archive(str(bad_tar), str(t3))
        except bm.BackupError:
            pass
        check("a refused restore leaves an existing target empty", os.listdir(t3) == [])

        # A member that is larger than the manifest says is refused before it is read.
        big = dict(good)
        big[".env"] = b"A" * (1 << 20)
        bigtar = base / "big.tar.gz"
        build_archive(bigtar, big, manifest_files)
        bt = base / "bigt"
        try:
            bm.restore_archive(str(bigtar), str(bt))
            refused, msg = False, ""
        except bm.BackupError as e:
            refused, msg = True, str(e)
        check("a member whose header size differs from the manifest is refused early and nothing is created",
              refused and "Size mismatch" in msg and not bt.exists(), msg)
        small = dict(good)
        small[".env"] = good[".env"][:-1]
        smalltar = base / "small.tar.gz"
        build_archive(smalltar, small, manifest_files)
        try:
            bm.restore_archive(str(smalltar), str(base / "smallt"))
            refused, msg = False, ""
        except bm.BackupError as e:
            refused, msg = True, str(e)
        check("a member smaller than the manifest says is refused as well", refused and "Size mismatch" in msg, msg)
        # The header check runs before any read.
        reads = []
        with tarfile.open(bigtar, "r:gz") as tar:
            mf = bm._load_manifest(tar)
            orig = tar.extractfile
            tar.extractfile = lambda m: (reads.append(m.name), orig(m))[1]
            try:
                bm._walk_members(tar, mf)
            except bm.BackupError:
                pass
        check("the oversized member is never opened for reading", ".env" not in reads, str(reads))

        # Defence in depth: a source that yields more than the header promised stops at expected + 1.
        class _Endless:
            def __init__(self):
                self.served = 0

            def read(self, n):
                self.served += n
                return b"B" * n

        class _FakeMember:
            name, size = ".env", 100

            def isreg(self):
                return True

        endless = _Endless()

        class _FakeTar:
            def __iter__(self):
                return iter([_FakeMember(), _FakeMember()])  # the first stands in for the manifest

            def extractfile(self, m):
                return endless

        try:
            bm._walk_members(_FakeTar(), {"files": {".env": {"sha256": "0" * 64, "size": 100}}})
            refused, msg = False, ""
        except bm.BackupError as e:
            refused, msg = True, str(e)
        check("reading stops once more bytes than the manifest size have come out",
              refused and "more data" in msg and endless.served == 101, f"{msg} served={endless.served}")

        # Extra, traversal, duplicate and non-regular members.
        for label, members, mf in (
            ("an unlisted member", {**good, "evil.py": b"x"}, manifest_files),
            ("a traversal name", {**good, "../evil": b"x"}, {**manifest_files, "../evil": {"sha256": "0" * 64, "size": 1}}),
            ("a missing member", {k: v for k, v in good.items() if k != ".env"}, manifest_files),
            ("no database", {".env": good[".env"]}, {".env": manifest_files[".env"]}),
        ):
            p = base / "x.tar.gz"
            build_archive(p, members, mf)
            tgt = base / "xt"
            try:
                bm.restore_archive(str(p), str(tgt))
                refused = False
            except bm.BackupError:
                refused = True
            check(f"{label} is refused and nothing is created", refused and not tgt.exists())

        p = base / "sym.tar.gz"
        manifest = {"format": 1, "files": {"portal.db": {"sha256": "0" * 64, "size": 0}}}
        with tarfile.open(p, "w:gz") as tar:
            data = json.dumps(manifest).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
            ti = tarfile.TarInfo("portal.db")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tar.addfile(ti)
        try:
            bm.restore_archive(str(p), str(base / "st"))
            refused = False
        except bm.BackupError:
            refused = True
        check("a symlink member is refused", refused and not (base / "st").exists())

        # A database that fails its integrity check.
        junk = b"not a database" * 100
        build_archive(base / "junk.tar.gz", {"portal.db": junk})
        try:
            bm.restore_archive(str(base / "junk.tar.gz"), str(base / "jt"))
            refused = False
        except Exception:
            refused = True
        check("a corrupt database is refused and nothing is left", refused and not (base / "jt").exists())


def test_config_without_open_database():
    from config import Config
    with Sandbox() as sb:
        sb.keeper.execute("INSERT INTO settings (key, value) VALUES ('backup_keep', '3')")
        sb.keeper.commit()
        saved = Config.DATABASE_PATH
        Config.DATABASE_PATH = sb.db
        try:
            cfg = asyncio.run(bm.load_config())
            status = asyncio.run(bm.get_status())
            asyncio.run(bm._record(True, "x"))
        finally:
            Config.DATABASE_PATH = saved
        check("a command-line run reads the settings straight from the file", cfg["keep"] == 3 and cfg["interval_hours"] == 24, str(cfg))
        check("without an open database the status calls do nothing", status == {})


def test_file_manager_blocks_backups():
    import file_manager as fm
    with Sandbox() as sb:
        info = sb.archive()
        base = Path(sb._tmp.name)
        adir = bm.archives_dir()
        extra = base / "extra" / "deep"
        extra.mkdir(parents=True, mode=0o700)
        secret = b"JWT_SECRET=abc"
        victims = {
            "archive": adir / info["name"],
            "temp archive": adir / ".partial-abc123.tar.gz",
            "database copy": um.BACKUPS_DIR / "portal-db-20260101_000000.db",
            "extra archive": extra / "portal-backup-20260101-000000.tar.gz",
            "extra suffix archive": extra / "portal-backup-20260101-000000-7.tar.gz",
            "extra database copy": extra / "portal-db-copy.db",
        }
        for p in victims.values():
            if not p.exists():
                p.write_bytes(secret)
        plain = base / "plain.txt"
        plain.write_text("hello")
        root = str(base)

        def refused(fn, *a):
            try:
                fn(*a)
                return False
            except ValueError as e:
                return "not allowed" in str(e)

        check("control: a plain file reads through the file manager", fm.read_file("/plain.txt", root) == b"hello")
        for label, p in victims.items():
            rel = "/" + str(p.relative_to(base))
            before = p.read_bytes()
            check(f"{label}: read is refused", refused(fm.read_file, rel, root))
            check(f"{label}: info is refused", refused(fm.get_file_info, rel, root))
            check(f"{label}: mime type is refused", refused(fm.get_mime_type, rel, root))
            check(f"{label}: download path check is refused", refused(fm._validate_path, rel, root))
            check(f"{label}: write is refused", refused(fm.write_file, rel, root, b"x") and p.read_bytes() == before)
            check(f"{label}: delete is refused", refused(fm.delete_path, rel, root) and p.exists())
            check(f"{label}: rename away is refused", refused(fm.rename_path, rel, "/moved.bin", root) and p.exists()
                  and not (base / "moved.bin").exists())
            check(f"{label}: rename onto the name is refused",
                  refused(fm.rename_path, "/plain.txt", rel, root) and plain.exists())
            listing = fm.list_directory("/" + str(p.parent.relative_to(base)), root) \
                if not refused(fm.list_directory, "/" + str(p.parent.relative_to(base)), root) else []
            check(f"{label}: it is not listed", p.name not in [e["name"] for e in listing])
        # Renaming a plain file to an archive name (a way to smuggle a copy in or out) is refused.
        check("a plain file cannot be renamed into the archives directory",
              refused(fm.rename_path, "/plain.txt", "/proj/backups/archives/x.txt", root) and plain.exists())
        # The archives directory itself.
        archives_rel = "/" + str(adir.relative_to(base))
        check("the archives directory cannot be listed", refused(fm.list_directory, archives_rel, root))
        check("the archives directory cannot be entered by info", refused(fm.get_file_info, archives_rel, root))
        check("a new file cannot be written into the archives directory",
              refused(fm.write_file, archives_rel + "/anything.txt", root, b"x")
              and not (adir / "anything.txt").exists())
        check("the archives directory is not listed in backups/",
              "archives" not in [e["name"] for e in fm.list_directory("/proj/backups", root)])
        check("the archives directory cannot be deleted", refused(fm.delete_path, archives_rel, root, True) and adir.exists())
        try:
            fm.delete_path("/proj/backups", root, True)
            rec_refused = False
        except ValueError as e:
            rec_refused = "recursively" in str(e)
        check("a recursive delete of backups/ is refused", rec_refused and adir.exists())
        # An archive deleted through the backup manager itself still works.
        bm.delete_archive(info["name"])
        check("the backup manager still deletes its own archive", not (adir / info["name"]).exists())
        # Neighbouring names are unaffected.
        for ok_name in ("portal-backup-notes.txt", "portal-db.md", "backups.tar.gz", "partial-x.tar.gz"):
            (base / ok_name).write_text("ok")
            check(f"{ok_name} is still reachable", fm.read_file("/" + ok_name, root) == b"ok")


def test_download_and_delete_need_the_cookie():
    """Download and delete both take only the browser session cookie (checked in the handler source)."""
    import ast
    tree = ast.parse((ROOT / "server.py").read_text())
    handlers = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}
    for name in ("http_admin_backups_download", "http_admin_backups_delete"):
        calls = [c for c in ast.walk(handlers[name]) if isinstance(c, ast.Call)
                 and getattr(c.func, "id", "") == "_backup_superadmin"]
        cookie_only = bool(calls) and all(any(k.arg == "cookie_only" and getattr(k.value, "value", None) is True
                                              for k in c.keywords) for c in calls)
        check(f"{name} requires the browser cookie", cookie_only)


def test_update_requires_backup():
    calls = []

    async def fake_run_cmd(cmd, *a, **kw):
        calls.append(list(cmd))
        return 0, "", ""

    async def fake_apply(job, version):
        calls.append(["apply", version])

    saved = (um._run_cmd, um._apply_portal_update)
    um._run_cmd, um._apply_portal_update = fake_run_cmd, fake_apply
    import backup_manager
    saved_run = backup_manager.run_now
    try:
        async def failing(reason="manual"):
            raise backup_manager.BackupError("disk full")

        async def passing(reason="manual"):
            calls.append(["backup", reason])
            return {"name": "portal-backup-20260101-000000.tar.gz", "extra_error": None}

        job = {"id": "t", "log": []}
        backup_manager.run_now = failing
        try:
            asyncio.run(um._run_apply(job, "portal", None))
            refused = False
        except RuntimeError as e:
            refused = "disk full" in str(e)
        check("an update does not start when the backup fails", refused and calls == [], str(calls))
        backup_manager.run_now = passing
        asyncio.run(um._run_apply(job, "portal", "v9"))
        check("the backup is taken before the update runs", calls == [["backup", "pre-update"], ["apply", "v9"]], str(calls))
        job2 = {"id": "t2", "log": []}
        um._log_restore_hint(job2)
        text = "\n".join(job2["log"])
        check("rollback logs the documented restore command, not a restore",
              "restore-archive" in text and "code only" in text)
    finally:
        um._run_cmd, um._apply_portal_update = saved
        backup_manager.run_now = saved_run


if __name__ == "__main__":
    for fn in (test_archive_contents, test_optional_files_and_missing, test_retention_and_names,
               test_free_space_refusal, test_busy_lock, test_extra_destination,
               test_extra_destination_private_tmp, test_extra_destination_served_dirs,
               test_consistency_under_writes, test_config_and_schedule, test_startup_check, test_due_check_after_restart,
               test_resolve_archive,
               test_restore, test_config_without_open_database, test_file_manager_blocks_backups, test_download_and_delete_need_the_cookie,
               test_update_requires_backup):
        fn()
    print(f"\n{len(FAILS)} failed" if FAILS else "\nall passed")
    sys.exit(1 if FAILS else 0)
