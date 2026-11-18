"""Smoke check: backup-db and update snapshots are private and consistent; rollback refuses a loosened snapshot."""

SNIPPET = r'''
import os, sqlite3, stat, subprocess, sys
r = subprocess.run([sys.executable, "server.py", "backup-db"],
                   capture_output=True, text=True)
print("rc=%d" % r.returncode)
print("stdout=%s" % r.stdout.strip())
print("stderr=%s" % r.stderr.strip())
lines = r.stdout.strip().splitlines()
out = lines[-1] if lines else ""
exists = os.path.isfile(out)
print("exists=%s" % exists)
if exists:
    print("mode=%04o" % stat.S_IMODE(os.stat(out).st_mode))
    db = sqlite3.connect(out)
    print("integrity=%s" % db.execute("PRAGMA integrity_check").fetchone()[0])
    print("users=%d" % db.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    db.close()
    print("sidefiles=%s" % any(os.path.exists(out + s) for s in ("-wal", "-shm")))
import tempfile
shared = tempfile.mkdtemp(prefix="smoke_shared_")
os.chmod(shared, 0o777)
r2 = subprocess.run([sys.executable, "server.py", "backup-db", "--out", os.path.join(shared, "x.db")],
                    capture_output=True, text=True)
print("shared_rc=%d" % r2.returncode)
print("shared_left=%s" % sorted(os.listdir(shared)))
os.rmdir(shared) if not os.listdir(shared) else None
# A symlink planted at the destination in a sticky shared directory must not be followed.
import shutil
base = tempfile.mkdtemp(prefix="smoke_link_")
sticky = os.path.join(base, "sticky")
target = os.path.join(base, "target")
os.mkdir(sticky)
os.chmod(sticky, 0o1777)
os.mkdir(target, 0o755)
os.symlink(os.path.join(target, "planted.db"), os.path.join(sticky, "x.db"))
r3 = subprocess.run([sys.executable, "server.py", "backup-db", "--out", os.path.join(sticky, "x.db")],
                    capture_output=True, text=True)
print("link_rc=%d" % r3.returncode)
print("link_target=%s" % sorted(os.listdir(target)))
print("link_sticky=%s" % sorted(os.listdir(sticky)))
shutil.rmtree(base, ignore_errors=True)
'''

SNAP_SNIPPET = r'''
import asyncio, os, shutil, sqlite3, stat, tempfile
import update_manager as um
from config import Config


# Nothing in this script may run git or any other external command.
async def _no_cmd(*a, **k):
    return 0, "", ""


async def _version():
    return "0.0-smoke"


um._run_cmd = _no_cmd
um._get_portal_version = _version

# A stage file that is group-writable before the snapshot: the snapshot must strip it.
gw = um.PORTAL_DIR / "smoke_gw.txt"
gw.write_text("x")
os.chmod(gw, 0o664)
print("gw_src=%04o" % stat.S_IMODE(os.stat(gw).st_mode))

# Write a row through a connection that stays open in WAL mode, without checkpointing.
db_path = Config.DATABASE_PATH
keeper = sqlite3.connect(db_path, timeout=30)
print("journal=%s" % keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0])
keeper.execute("PRAGMA wal_autocheckpoint=0")
keeper.execute("CREATE TABLE IF NOT EXISTS smoke_wal_marker (v TEXT)")
keeper.execute("INSERT INTO smoke_wal_marker (v) VALUES ('wal-only-row')")
keeper.commit()
# The main file alone must not have the row yet, otherwise the check below proves nothing.
raw_dir = tempfile.mkdtemp(prefix="smoke_raw_")
raw = os.path.join(raw_dir, "raw.db")
shutil.copyfile(db_path, raw)
try:
    c = sqlite3.connect(raw)
    raw_rows = c.execute("SELECT COUNT(*) FROM smoke_wal_marker").fetchone()[0]
    c.close()
except sqlite3.Error:
    raw_rows = 0
shutil.rmtree(raw_dir, ignore_errors=True)
print("raw_has_row=%s" % (raw_rows > 0))

meta = asyncio.run(um.create_snapshot("smoke"))
snap = um.SNAPSHOTS_DIR / meta["id"]
print("dirmode=%04o" % stat.S_IMODE(os.stat(snap).st_mode))
print("metamode=%04o" % stat.S_IMODE(os.stat(um.SNAPSHOTS_DIR / (meta["id"] + ".json")).st_mode))
print("backupsmode=%04o" % stat.S_IMODE(os.stat(um.BACKUPS_DIR).st_mode))
print("snapsmode=%04o" % stat.S_IMODE(os.stat(um.SNAPSHOTS_DIR).st_mode))
print("integrity=%s" % meta.get("db_integrity"))
print("hasdb=%s" % (snap / "portal.db").is_file())
print("wal=%s" % any((snap / ("portal.db" + s)).exists() for s in ("-wal", "-shm")))
c = sqlite3.connect(snap / "portal.db")
print("snap_has_row=%s" % (c.execute("SELECT COUNT(*) FROM smoke_wal_marker").fetchone()[0] > 0))
c.close()
# Leave the stage schema as it was (the runner compares it before and after).
keeper.execute("DROP TABLE smoke_wal_marker")
keeper.commit()
keeper.close()
print("gw_snap=%04o" % stat.S_IMODE(os.stat(snap / "smoke_gw.txt").st_mode))
loose = 0
for dp, dns, fns in os.walk(snap):
    for n in dns + fns:
        p = os.path.join(dp, n)
        if not os.path.islink(p) and os.stat(p).st_mode & 0o022:
            loose += 1
print("loose=%d" % loose)
skip = um._ROLLBACK_PRESERVE_DIRS | um._ROLLBACK_PRESERVE_FILES
um._check_snapshot_restorable(snap, skip)
print("clean_ok=True")


def _refused(needle):
    try:
        asyncio.run(um._apply_rollback({"id": "s", "log": []}, meta["id"]))
        return False
    except RuntimeError as e:
        return "Refusing to roll back" in str(e) and needle in str(e)


# Drive the real rollback path (external commands are stubbed above).
victim = snap / "server.py"
os.chmod(victim, 0o664)
print("refused=%s" % _refused("server.py"))
os.chmod(victim, 0o644)
os.chmod(um.SNAPSHOTS_DIR, 0o770)
print("refused_dir=%s" % _refused("snapshots/"))
os.chmod(um.SNAPSHOTS_DIR, 0o700)
'''


def _parse(text):
    vals = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip()
    return vals


async def run(ctx):
    rc, out = await ctx.run_py(SNIPPET)
    v = _parse(out)
    ctx.ok("snapshots: backup-db exits 0", rc == 0 and v.get("rc") == "0", out.strip()[-300:])
    ctx.ok("snapshots: backup-db file exists", v.get("exists") == "True")
    ctx.ok("snapshots: backup-db file mode is 0600", v.get("mode") == "0600", f"mode={v.get('mode')}")
    ctx.ok("snapshots: backup-db copy passes integrity_check", v.get("integrity") == "ok",
           f"integrity={v.get('integrity')}")
    ctx.ok("snapshots: backup-db copy holds the admin account",
           v.get("users", "").isdigit() and int(v["users"]) >= 1, f"users={v.get('users')}")
    ctx.ok("snapshots: backup-db leaves no WAL side files", v.get("sidefiles") == "False")
    ctx.ok("snapshots: backup-db refuses a world-writable destination directory and writes nothing",
           v.get("shared_rc") == "1" and v.get("shared_left") == "[]",
           f"rc={v.get('shared_rc')} left={v.get('shared_left')}")
    ctx.ok("snapshots: backup-db does not follow a symlink planted at the destination",
           v.get("link_rc") == "1" and v.get("link_target") == "[]" and v.get("link_sticky") == "['x.db']",
           f"rc={v.get('link_rc')} target={v.get('link_target')} sticky={v.get('link_sticky')}")

    rc, out = await ctx.run_py(SNAP_SNIPPET)
    v = _parse(out)
    tail = out.strip()[-400:]
    ctx.ok("snapshots: create_snapshot directory mode is 0700", v.get("dirmode") == "0700", f"dirmode={v.get('dirmode')} {tail if rc else ''}")
    ctx.ok("snapshots: snapshot metadata file is 0600", v.get("metamode") == "0600", f"metamode={v.get('metamode')}")
    ctx.ok("snapshots: backups and snapshots directories are 0700",
           v.get("backupsmode") == "0700" and v.get("snapsmode") == "0700",
           f"backups={v.get('backupsmode')} snapshots={v.get('snapsmode')}")
    ctx.ok("snapshots: a group-writable source file is group-writable before the snapshot",
           v.get("gw_src") == "0664", f"gw_src={v.get('gw_src')}")
    ctx.ok("snapshots: group-write bit is stripped from the copied file", v.get("gw_snap") == "0644",
           f"gw_snap={v.get('gw_snap')}")
    ctx.ok("snapshots: snapshot has nothing group/other writable", v.get("loose") == "0", f"loose={v.get('loose')}")
    ctx.ok("snapshots: snapshot database copy passes integrity_check",
           v.get("integrity") == "ok" and v.get("hasdb") == "True", f"integrity={v.get('integrity')}")
    ctx.ok("snapshots: snapshot has no WAL side files", v.get("wal") == "False")
    if v.get("journal") != "wal" or v.get("raw_has_row") != "False":
        ctx.skip("snapshots: snapshot database copy holds a row that exists only in the WAL",
                 f"precondition not met: journal={v.get('journal')} raw_has_row={v.get('raw_has_row')}")
    else:
        ctx.ok("snapshots: snapshot database copy holds a row that exists only in the WAL",
               v.get("snap_has_row") == "True", f"snap_has_row={v.get('snap_has_row')}")
    ctx.ok("snapshots: fresh snapshot is accepted for rollback", v.get("clean_ok") == "True", tail)
    ctx.ok("snapshots: rollback refuses a group-writable snapshot file", v.get("refused") == "True",
           f"refused={v.get('refused')}")
    ctx.ok("snapshots: rollback refuses a group-writable snapshots directory", v.get("refused_dir") == "True",
           f"refused_dir={v.get('refused_dir')}")
