"""Member uploads in backup archives (setting "Include uploads", off by default).

Run: venv/bin/python tests/test_backup_uploads.py   (exit code 0 means pass)

Everything happens in a temporary directory tree and a temporary database; nothing outside it is touched and
no server is started. Every test has its own deadline: a test that hangs prints FAIL and the run goes on.
"""
import asyncio
import hashlib
import io
import json
import os
import shutil
import signal
import sqlite3
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import alerts  # noqa: E402
import backup_manager as bm  # noqa: E402
import update_manager as um  # noqa: E402

FAILS = []
TEST_DEADLINE = 60


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"  ({detail})" if detail and not cond else ""), flush=True)
    if not cond:
        FAILS.append(name)


class Sandbox:
    """A throwaway project tree with a database, .env, salt, invite code and a static/uploads tree."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="bkup_")
        self.base = Path(self._tmp.name)
        self.root = self.base / "proj"
        self.root.mkdir(mode=0o755)
        self._saved = {}

    def __enter__(self):
        for name in ("PORTAL_DIR", "BACKUPS_DIR"):
            self._saved[name] = getattr(um, name)
        um.PORTAL_DIR = self.root
        um.BACKUPS_DIR = self.root / "backups"
        self.db = str(self.root / "portal.db")
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
        conn.execute("INSERT INTO settings (key, value) VALUES ('encryption_key_version', '2')")
        conn.commit()
        conn.close()
        (self.root / ".env").write_text("JWT_SECRET=abc\nPORT=8461\n")
        (self.root / ".encryption_salt").write_bytes(b"\x01\x02salt")
        (self.root / ".invite_code").write_text("2026-01-01\nCODE\n")
        self.uploads = self.root / "static" / "uploads"
        return self

    def __exit__(self, *exc):
        for name, val in self._saved.items():
            setattr(um, name, val)
        self._tmp.cleanup()

    def put(self, rel, data: bytes):
        p = self.uploads / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def fill(self):
        self.put("chat/a.png", b"\x89PNG-marker-AAAA" * 50)
        self.put("chat/sub/b.bin", os.urandom(3000))
        self.put("thumbnails/t.jpg", b"JPEGDATA" * 100)
        self.put("emotes/e.gif", b"GIF89a" + b"\x00" * 10)
        self.put("empty.txt", b"")

    def archive(self, **kw):
        return bm.create_archive(self.db, kw.pop("version", "v0.test"), **kw)


def tree(path: Path) -> dict:
    out = {}
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(path).as_posix()] = p.read_bytes()
    return out


def names_in(path) -> list:
    with tarfile.open(path, "r:gz") as tar:
        return [m.name for m in tar]


def manifest_of(path) -> dict:
    with tarfile.open(path, "r:gz") as tar:
        return json.loads(tar.extractfile(tar.next()).read())


def with_deadline(name, fn):
    def on_alarm(signum, frame):
        raise TimeoutError(f"{name} did not finish in {TEST_DEADLINE} s")

    old = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(TEST_DEADLINE)
    try:
        fn()
    except BaseException as e:  # a failing test prints FAIL and the run goes on
        check(f"{name} ran to the end", False, f"{type(e).__name__}: {e}")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


# ---------------------------------------------------------------------------

def test_setting_off_is_unchanged():
    # Regression guard: this passes on the code before the change too (the setting is off by default).
    with Sandbox() as sb:
        sb.fill()
        info = sb.archive()
        check("off: layout is manifest, database and the state files only",
              names_in(info["path"]) == ["manifest.json", "portal.db", ".env", ".encryption_salt", ".invite_code"],
              str(names_in(info["path"])))
        m = manifest_of(info["path"])
        check("off: the manifest has no uploads section", "uploads" not in m, str(sorted(m)))
        check("off: parse_config default is off", bm.parse_config({})["include_uploads"] is False)


def test_round_trip():
    with Sandbox() as sb:
        sb.fill()
        info = sb.archive(include_uploads=True)
        names = names_in(info["path"])
        check("on: manifest first, then database, state files, uploads, index last",
              names[:5] == ["manifest.json", "portal.db", ".env", ".encryption_salt", ".invite_code"]
              and names[-1] == bm.UPLOADS_INDEX and "uploads/chat/a.png" in names and "uploads/empty.txt" in names,
              str(names))
        m = manifest_of(info["path"])
        check("on: the manifest announces the uploads and lists them outside files",
              m.get("uploads", {}).get("included") is True and not any(k.startswith("uploads") for k in m["files"]),
              json.dumps(m.get("uploads")))
        check("on: result carries the counts", info["uploads"]["files"] == 5, str(info.get("uploads")))
        dest = sb.base / "restored-uploads"
        res = bm.restore_uploads(info["path"], str(dest))
        check("round trip: identical bytes", tree(dest) == tree(sb.uploads), str(sorted(tree(dest))))
        check("round trip: counts", (res["restored"], res["skipped_existing"], res["refused"]) == (5, 0, 0), str(res))
        # the database restore with the flag, and without it
        plain = sb.base / "plain"
        bm.restore_archive(info["path"], str(plain))
        check("db restore without the flag restores the database only",
              (plain / "portal.db").is_file() and not (plain / "static").exists(), str(sorted(os.listdir(plain))))
        full = sb.base / "full"
        r = bm.restore_archive(info["path"], str(full), uploads=True)
        check("db restore with uploads restores both", (full / "portal.db").is_file()
              and tree(full / "static" / "uploads") == tree(sb.uploads) and r["uploads"]["restored"] == 5, str(r.get("uploads")))
        old = sb.archive()
        try:
            bm.restore_uploads(old["path"], str(sb.base / "none"))
            check("restoring uploads from an archive without any is refused clearly", False)
        except bm.BackupError as e:
            check("restoring uploads from an archive without any is refused clearly", "no uploads" in str(e).lower(), str(e))
        res = bm.restore_archive(old["path"], str(sb.base / "oldplain"))
        check("an archive without uploads restores as before", (sb.base / "oldplain" / "portal.db").is_file())
        info2 = sb.archive(include_uploads=True)
        lst = {a["name"]: a for a in bm.list_archives()}
        check("the list shows the uploads of an archive and its size",
              lst[info2["name"]]["uploads"]["included"] is True and lst[info2["name"]]["size"] > 0
              and lst[old["name"]].get("uploads") is None, str(lst[info2["name"]]))
        check("retention counts archives as before", len(bm.list_archives()) == 3 and
              len(sb.archive(keep=2) and bm.list_archives()) == 2)


def test_links():
    with Sandbox() as sb:
        sb.fill()
        outside = sb.base / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("SECRET-OUTSIDE")
        disk = sb.base / "otherdisk"
        (disk / "x").mkdir(parents=True)
        (disk / "x" / "f.txt").write_text("on the other disk")
        (disk / "x" / "escape").symlink_to(outside / "secret.txt")
        (disk / "x" / "escdir").symlink_to(outside)
        (sb.uploads / "avatars").symlink_to(disk / "x")           # a folder that is itself a link: served as it was
        (sb.uploads / "chat" / "inside-link.png").symlink_to(sb.uploads / "chat" / "a.png")
        (sb.uploads / "chat" / "out-link").symlink_to(outside / "secret.txt")
        (sb.uploads / "chat" / "out-dir").symlink_to(outside)
        (sb.uploads / "chat" / "loop").symlink_to(sb.uploads)
        (sb.uploads / "top-out").symlink_to(outside / "secret.txt")
        info = sb.archive(include_uploads=True)
        names = names_in(info["path"])
        check("a link to a folder keeps its files", "uploads/avatars/f.txt" in names, str(names))
        check("a link to a file inside the uploads is followed", "uploads/chat/inside-link.png" in names)
        for bad in ("out-link", "out-dir", "loop"):
            check(f"a link out of the uploads is not followed ({bad})",
                  not any(n.startswith(f"uploads/chat/{bad}") for n in names), str(names))
        check("links out of a linked folder are not followed",
              not any(n.startswith(("uploads/avatars/escape", "uploads/avatars/escdir")) for n in names))
        check("a top-level file link out is not followed", "uploads/top-out" not in names)
        res = bm.restore_uploads(info["path"], str(sb.base / "r"))
        check("no secret outside the uploads is in the restore", "SECRET-OUTSIDE" not in json.dumps(
            {k: v.decode("latin1") for k, v in tree(sb.base / "r").items()}))
        check("the skipped links are counted", info["uploads"]["skipped_outside"] >= 4, str(info["uploads"]))


def crafted(path, members, index_files=None, manifest_uploads=True):
    """Write an archive by hand: manifest, database, then *members* [(name, type, data)], then an index."""
    db = sqlite3.connect(":memory:")
    db.close()
    tmpdb = path + ".db"
    c = sqlite3.connect(tmpdb)
    c.execute("CREATE TABLE settings (key TEXT, value TEXT)")
    c.commit()
    c.close()
    dbbytes = open(tmpdb, "rb").read()
    os.unlink(tmpdb)
    files = {"portal.db": {"sha256": hashlib.sha256(dbbytes).hexdigest(), "size": len(dbbytes)}}
    manifest = {"format": 1, "created_at": "2026-01-01T00:00:00+00:00", "portal_version": "t", "database": "portal.db",
                "schema": {}, "files": files}
    if manifest_uploads:
        manifest["uploads"] = {"included": True, "index": bm.UPLOADS_INDEX}
    index = {"format": 1, "files": {}}
    with tarfile.open(path, "w:gz") as tar:
        def add(name, data, typ=tarfile.REGTYPE, linkname=""):
            ti = tarfile.TarInfo(name)
            ti.type = typ
            ti.size = len(data) if typ == tarfile.REGTYPE else 0
            ti.linkname = linkname
            ti.mode = 0o644
            tar.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)

        add("manifest.json", json.dumps(manifest).encode())
        add("portal.db", dbbytes)
        for name, typ, data in members:
            add(name, data if typ == tarfile.REGTYPE else b"", typ, "/etc/passwd" if typ == tarfile.SYMTYPE else "")
            if typ == tarfile.REGTYPE and index_files is None:
                index["files"][name[len("uploads/"):] if name.startswith("uploads/") else name] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        if index_files is not None:
            index["files"] = index_files
        add(bm.UPLOADS_INDEX, json.dumps(index).encode())


def test_crafted_archive():
    with Sandbox() as sb:
        arc = str(sb.base / "crafted.tar.gz")
        R = tarfile.REGTYPE
        crafted(arc, [
            ("uploads/ok.txt", R, b"fine"),
            ("uploads/../evil.txt", R, b"EVIL1"),
            ("uploads/chat/../../evil2.txt", R, b"EVIL2"),
            ("uploads//double.txt", R, b"EVIL4"),
            ("uploads/link", tarfile.SYMTYPE, b""),
            ("uploads/dev", tarfile.CHRTYPE, b""),
            ("uploads/dir", tarfile.DIRTYPE, b""),
            ("uploads/chat/sub/x.txt", R, b"nested-through-link"),
        ])
        dest = sb.base / "dest"
        (dest / "chat").mkdir(parents=True)
        elsewhere = sb.base / "elsewhere"
        elsewhere.mkdir()
        (dest / "chat" / "sub").symlink_to(elsewhere)             # a link that already sits in the target
        res = bm.restore_uploads(arc, str(dest))
        got = tree(dest)
        check("the good member is restored", got.get("ok.txt") == b"fine", str(got))
        check("nothing is written through a link in the target", os.listdir(elsewhere) == [], str(os.listdir(elsewhere)))
        check("nothing landed outside the target",
              not (sb.base / "evil.txt").exists() and not (sb.base / "evil2.txt").exists()
              )
        check("no link, device or odd name was created", set(got) == {"ok.txt"}
              and not os.path.lexists(dest / "link") and not os.path.lexists(dest / "dev"), str(got))
        check("refusals are counted", res["restored"] == 1 and res["refused"] >= 6, str(res))
        # a member outside the uploads folder (an absolute path) fails the whole restore, like any unknown member
        arcabs = str(sb.base / "crafted-abs.tar.gz")
        crafted(arcabs, [("uploads/ok.txt", R, b"fine"), ("/abs-evil.txt", R, b"EVIL3")])
        dabs = sb.base / "dabs"
        try:
            bm.restore_uploads(arcabs, str(dabs))
            check("an absolute member is refused", False)
        except bm.BackupError as e:
            check("an absolute member is refused", "unexpected member" in str(e).lower(), str(e))
        check("an absolute member writes nothing", not Path("/abs-evil.txt").exists() and (not dabs.exists() or os.listdir(dabs) == []))
        # an uploads member the index does not list is not restored
        arc2 = str(sb.base / "crafted2.tar.gz")
        crafted(arc2, [("uploads/unlisted.txt", R, b"x"), ("uploads/listed.txt", R, b"y")],
                index_files={"listed.txt": {"sha256": hashlib.sha256(b"y").hexdigest(), "size": 1}})
        d2 = sb.base / "d2"
        r2 = bm.restore_uploads(arc2, str(d2))
        check("an uploads member that the index does not list is refused", set(tree(d2)) == {"listed.txt"} and r2["refused"] == 1, str(r2))
        # a member whose bytes do not match the index fails the whole restore and writes nothing
        arc3 = str(sb.base / "crafted3.tar.gz")
        crafted(arc3, [("uploads/a.txt", R, b"data")],
                index_files={"a.txt": {"sha256": "0" * 64, "size": 4}})
        d3 = sb.base / "d3"
        try:
            bm.restore_uploads(arc3, str(d3))
            check("a damaged uploads member is refused", False)
        except bm.BackupError as e:
            check("a damaged uploads member is refused", "checksum" in str(e).lower(), str(e))
        check("a refused restore wrote nothing", not d3.exists() or os.listdir(d3) == [])
        # the live installation is never a target
        try:
            bm.restore_uploads(arc, str(sb.uploads))
            check("restoring uploads into the live uploads folder is refused", False)
        except bm.BackupError as e:
            check("restoring uploads into the live uploads folder is refused", "live" in str(e).lower(), str(e))
        # database restore with the flag also refuses the unsafe ones
        t = sb.base / "dbt"
        r4 = bm.restore_archive(arc, str(t), uploads=True)
        check("a db restore with uploads restores the safe members only",
              set(tree(t / "static" / "uploads")) == {"ok.txt", "chat/sub/x.txt"} and r4["uploads"]["refused"] >= 6,
              str((sorted(tree(t / "static" / "uploads")), r4["uploads"])))
        # a db-only restore ignores the uploads members
        t2 = sb.base / "dbt2"
        bm.restore_archive(arc, str(t2))
        check("a db-only restore ignores the uploads members", not (t2 / "static").exists())


def test_existing_files():
    with Sandbox() as sb:
        sb.fill()
        info = sb.archive(include_uploads=True)
        dest = sb.base / "dest"
        (dest / "chat").mkdir(parents=True)
        (dest / "chat" / "a.png").write_bytes(b"MINE")
        (dest / "keep-me.txt").write_bytes(b"not in the archive")
        res = bm.restore_uploads(info["path"], str(dest))
        check("an existing file is kept without the overwrite flag",
              (dest / "chat" / "a.png").read_bytes() == b"MINE" and res["skipped_existing"] == 1 and res["restored"] == 4, str(res))
        check("nothing existing is deleted", (dest / "keep-me.txt").read_bytes() == b"not in the archive")
        res = bm.restore_uploads(info["path"], str(dest), overwrite=True)
        check("with the overwrite flag the file is replaced",
              (dest / "chat" / "a.png").read_bytes() == (sb.uploads / "chat" / "a.png").read_bytes() and res["skipped_existing"] == 0, str(res))
        check("an overwrite still deletes nothing", (dest / "keep-me.txt").exists()
              and not [n for n in os.listdir(dest / "chat") if n.startswith(".restore")])
        # an existing directory where a file belongs is refused, not replaced
        d2 = sb.base / "d2"
        (d2 / "chat" / "a.png").mkdir(parents=True)
        res = bm.restore_uploads(info["path"], str(d2), overwrite=True)
        check("a directory in the way is refused", (d2 / "chat" / "a.png").is_dir() and res["refused"] == 1, str(res))


def test_low_space():
    with Sandbox() as sb:
        sb.fill()
        big = sb.uploads / "chat" / "big.bin"
        with open(big, "wb") as f:
            f.truncate(40 * 1024 * 1024)                           # sparse: no real disk is used
        real = shutil.disk_usage
        shutil.disk_usage = lambda p: shutil._ntuple_diskusage(100 * 1024 * 1024, 80 * 1024 * 1024, 20 * 1024 * 1024)
        try:
            info = sb.archive(include_uploads=True)
        finally:
            shutil.disk_usage = real
        names = names_in(info["path"])
        check("too little space gives a database-only archive", not any(n.startswith("uploads") for n in names) and "portal.db" in names, str(names))
        m = manifest_of(info["path"])
        check("the manifest says the uploads were skipped for space",
              m["uploads"]["included"] is False and m["uploads"]["skipped"] == "uploads skipped: not enough space", json.dumps(m.get("uploads")))
        check("the result carries the note", info.get("uploads_note") == "uploads skipped: not enough space", str(info.get("uploads_note")))
        lst = bm.list_archives()
        check("the backup list shows it", lst[0]["uploads"]["skipped"] == "uploads skipped: not enough space", str(lst[0]))
        # switching the setting on is refused with the same guard
        shutil.disk_usage = lambda p: shutil._ntuple_diskusage(100 * 1024 * 1024, 80 * 1024 * 1024, 20 * 1024 * 1024)
        try:
            out, errors = bm.validate_config_update({"include_uploads": True})
        finally:
            shutil.disk_usage = real
        check("switching the setting on with too little space is refused", errors and not out and "space" in errors[0].lower(), str(errors))
        out, errors = bm.validate_config_update({"include_uploads": True})
        check("switching it on with enough space is accepted", out == {"backup_include_uploads": "true"} and not errors, str((out, errors)))
        out, errors = bm.validate_config_update({"include_uploads": False})
        check("switching it off needs no check", out == {"backup_include_uploads": "false"})
        out, errors = bm.validate_config_update({"include_uploads": "yes"})
        check("a non-boolean is refused", errors and not out)


def test_vanishing_file():
    with Sandbox() as sb:
        sb.fill()
        sb.put("chat/c.png", b"will vanish")
        real_walk = bm._walk_uploads

        calls = []

        def walk(*a, **k):
            calls.append(1)
            first = len(calls) == 2                                # the first walk is the estimate
            for item in real_walk(*a, **k):
                if first:
                    first = False
                    victim = sb.uploads / "chat" / "c.png"
                    if victim.exists():
                        victim.unlink()                            # vanishes after it was listed
                yield item

        bm._walk_uploads = walk
        try:
            info = sb.archive(include_uploads=True)
        finally:
            bm._walk_uploads = real_walk
        check("a file deleted during the walk does not fail the backup",
              info["uploads"]["skipped_vanished"] == 1 and info["uploads"]["files"] == 5, str(info["uploads"]))
        res = bm.restore_uploads(info["path"], str(sb.base / "r"))
        check("the vanished file is simply not in the restore", "chat/c.png" not in tree(sb.base / "r") and res["refused"] == 0, str(res))
        # the reader gives exactly the announced size: padded when the file shrank, cut when it grew
        r = bm._FixedReader(io.BytesIO(b"abc"), 8)
        data = r.read(100) + r.read(100)
        check("a shrunk file is padded to its announced size and flagged", len(data) == 8 and r.short and r.sha256() == hashlib.sha256(data).hexdigest())
        r = bm._FixedReader(io.BytesIO(b"abcdefghij"), 4)
        data = r.read(100)
        check("a grown file is cut at its announced size", data == b"abcd" and r.read(10) == b"")
        # a file whose size changed while it was read is not listed in the index
        p = sb.uploads / "chat" / "a.png"
        orig = bm._FixedReader.read

        def growing(self, n=-1):
            out = orig(self, n)
            if not getattr(self, "_grown", False):
                self._grown = True
                with open(p, "ab") as f:
                    f.write(b"more")
            return out

        bm._FixedReader.read = growing
        try:
            info = sb.archive(include_uploads=True)
        finally:
            bm._FixedReader.read = orig
        check("a file that changed while it was read is skipped and counted", info["uploads"]["skipped_changed"] >= 1, str(info["uploads"]))
        d = sb.base / "r2"
        bm.restore_uploads(info["path"], str(d))
        check("a changed file is not restored", not (d / "chat" / "a.png").exists(), str(sorted(tree(d))))


def test_run_now_and_alert():
    sent = []
    calls = []

    async def fire(event, payload):
        sent.append((event, payload))
        return 1

    cfg = {"keep": 7, "extra_dir": "", "include_uploads": True}
    info = {"name": "portal-1.tar", "pruned": [], "extra_error": None, "uploads_note": "uploads skipped: not enough space"}

    async def fake_cfg():
        return cfg

    async def fake_version():
        return "1.0.0"

    recorded = []

    async def fake_record(ok, name="", error=""):
        recorded.append((ok, name, error))

    def fake_create(db_path, version, keep, extra_dir, wait=0, include_uploads=False):
        calls.append(include_uploads)
        return info

    async def main():
        alerts.reset_state()
        alerts.bind(fire=fire)
        saved = (bm.load_config, bm.um._get_portal_version, bm.create_archive, bm._record)
        bm.load_config, bm.um._get_portal_version, bm._record = fake_cfg, fake_version, fake_record
        bm.create_archive = fake_create
        try:
            for reason in ("manual", "scheduled", "pre-update"):
                await bm.run_now(reason)
            for _ in range(5):
                await asyncio.sleep(0)
            while alerts._tasks:
                await asyncio.gather(*list(alerts._tasks), return_exceptions=True)
        finally:
            bm.load_config, bm.um._get_portal_version, bm.create_archive, bm._record = saved
            alerts.unbind()

    asyncio.run(asyncio.wait_for(main(), 30))
    check("manual and scheduled backups follow the setting, the pre-update backup never adds uploads",
          calls == [True, True, False], str(calls))
    ev = [e for e, _ in sent]
    check("a skipped uploads part sends backup.failed (not backup.ok)", ev.count("backup.failed") >= 1, str(ev))
    check("the note reaches the saved result", any("not enough space" in r[2] for r in recorded), str(recorded))


def test_estimate_and_settings():
    with Sandbox() as sb:
        sb.fill()
        est = bm.estimate_uploads()
        total = sum(len(v) for v in tree(sb.uploads).values())
        check("the estimate is the sum of the file sizes", est["files"] == 5 and est["bytes"] == total, str(est))
        shutil.rmtree(sb.uploads)
        est = bm.estimate_uploads()
        check("a missing uploads folder estimates zero", est["files"] == 0 and est["bytes"] == 0, str(est))
        info = sb.archive(include_uploads=True)
        check("a missing uploads folder is no failure", info["uploads"]["files"] == 0, str(info.get("uploads")))
        cfg = bm.parse_config({"backup_include_uploads": "true"})
        check("the setting is read", cfg["include_uploads"] is True)


def test_old_archives_and_rollback_note():
    """An archive made by the real 1.24.1 (tests/fixtures/portal-backup-v1.24.1.tar.gz, made by that release with
    toy data: manifest without an "uploads" key) restores unchanged through the command line of this release;
    the admin card says archives with uploads need 1.24.2."""
    import subprocess
    fixture = ROOT / "tests" / "fixtures" / "portal-backup-v1.24.1.tar.gz"
    base = Path(tempfile.mkdtemp(prefix="bkold_"))
    try:
        with tarfile.open(fixture, "r:gz") as tar:
            manifest = json.loads(tar.extractfile("manifest.json").read())
            members = {m.name: tar.extractfile(m).read() for m in tar if m.name != "manifest.json"}
        check("the fixture is an archive of 1.24.1 without uploads",
              manifest["portal_version"] == "v1.24.1" and "uploads" not in manifest
              and not any(n.startswith("uploads/") for n in members), str(manifest.get("portal_version")))
        res = bm.restore_archive(str(fixture), str(base / "viafn"))
        check("an archive of 1.24.1 restores through the function", sorted(res["files"]) == sorted(members), str(res))
        out = base / "viacli"
        env = dict(os.environ, JWT_SECRET="x" * 64)
        cp = subprocess.run([sys.executable, str(ROOT / "server.py"), "restore-archive", str(fixture), "--into", str(out)],
                            cwd=str(base), env=env, capture_output=True, text=True, timeout=60)
        check("the command line of this release restores an archive of 1.24.1 unchanged",
              cp.returncode == 0 and all((out / n).read_bytes() == d for n, d in members.items())
              and not (out / "static").exists(), f"rc={cp.returncode} {cp.stdout[-200:]} {cp.stderr[-300:]}")
        cp = subprocess.run([sys.executable, str(ROOT / "server.py"), "restore-archive", str(fixture), "--uploads-into", str(base / "up")],
                            cwd=str(base), env=env, capture_output=True, text=True, timeout=60)
        check("an archive without uploads is refused for the uploads restore and writes nothing",
              cp.returncode == 1 and "holds no uploads" in cp.stderr and not (base / "up").exists(), cp.stderr[-200:])
    finally:
        shutil.rmtree(base, ignore_errors=True)
    html = (ROOT / "static" / "admin.html").read_text(encoding="utf-8")
    i = html.index("bk-uploads-note")
    near = html[i:i + 4000]
    check("the Backups card says archives with uploads cannot be restored by 1.24.1 or earlier",
          "cannot be restored by version 1.24.1 or earlier" in near and "1.24.2 or later" in near)


def test_link_into_backups_and_restore_targets():
    with Sandbox() as sb:
        sb.fill()
        first = sb.archive(include_uploads=True)
        # a link at the top of the uploads that leads to the backups folder must not be followed: every
        # archive would otherwise hold the earlier ones and the database copy
        (sb.uploads / "bk").symlink_to(bm.um.BACKUPS_DIR)
        (sb.uploads / "bk2").symlink_to(bm.archives_dir())
        info = sb.archive(include_uploads=True)
        names = names_in(info["path"])
        check("a link to the backups folder is not followed",
              not any(n.startswith(("uploads/bk/", "uploads/bk2/")) for n in names), str(names[:12]))
        check("the other files are still in the archive", "uploads/chat/a.png" in names)
        # a restore target that is a link is refused; one owned by another account is refused
        real = sb.base / "real"
        real.mkdir()
        (sb.base / "lnk").symlink_to(real)
        try:
            bm.restore_uploads(info["path"], str(sb.base / "lnk"))
            refused = False
        except bm.BackupError:
            refused = True
        check("a restore target that is a link is refused", refused and not os.listdir(real))
        saved = os.geteuid
        os.geteuid = lambda: saved() + 1
        try:
            try:
                bm.restore_uploads(info["path"], str(real))
                refused = False
            except bm.BackupError as e:
                refused = "another account" in str(e)
        finally:
            os.geteuid = saved
        check("a restore target owned by another account is refused and nothing is written", refused and not os.listdir(real))
        # a target that does not exist yet needs a parent that is ours; --into with uploads needs a target that is ours
        saved = os.geteuid
        os.geteuid = lambda: saved() + 1
        try:
            fresh = sb.base / "fresh-name"
            for label, call in (
                ("a new uploads target whose parent belongs to another account",
                 lambda: bm.restore_uploads(info["path"], str(fresh))),
                ("a database restore with uploads into a folder of another account",
                 lambda: bm.restore_archive(info["path"], str(sb.base / "fresh2"), uploads=True)),
            ):
                try:
                    call()
                    refused = False
                except bm.BackupError as e:
                    refused = "another account" in str(e)
                check(f"{label} is refused", refused and not fresh.exists() and not (sb.base / "fresh2").exists())
            res = bm.restore_archive(info["path"], str(sb.base / "fresh3"))
            check("the database-only restore does not look at the owner", "portal.db" in res["files"])
        finally:
            os.geteuid = saved
        # the folder is opened without following a link even when the check before it was passed
        h = bm._UploadsRestore(str(sb.base / "lnk"))
        h.index = {}
        h.phase = "write"
        member = tarfile.TarInfo("uploads/chat/a.png")
        h.seen["chat/a.png"] = ("0" * 64, 1)
        try:
            h._store(None, member, "chat/a.png")
        except OSError:
            pass
        check("the restore target is opened without following a link", not os.listdir(real))


def test_restore_refuses_the_live_uploads_behind_a_link():
    with Sandbox() as sb:
        sb.fill()
        info = sb.archive(include_uploads=True)
        disk = sb.base / "otherdisk"
        shutil.move(str(sb.uploads), str(disk))
        sb.uploads.symlink_to(disk)             # the live uploads folder lives on another disk
        before = tree(disk)
        for target in (disk, disk / "chat"):
            try:
                bm.restore_uploads(info["path"], str(target), overwrite=True)
                refused = False
            except bm.BackupError as e:
                refused = "live installation" in str(e)
            check(f"a restore into the live uploads folder behind a link is refused ({target.name})", refused)
        check("... and nothing there changed", tree(disk) == before)


def main():
    for name, fn in sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)):
        with_deadline(name, fn)
    if FAILS:
        print(f"\ntest_backup_uploads: {len(FAILS)} FAILED: " + "; ".join(FAILS))
        sys.exit(1)
    print("\ntest_backup_uploads: all checks passed")


main()
