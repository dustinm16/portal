"""The boot/cleanup sweep delivers only into the owner's current storage root.

A sidecar names the remote session folder of the time of recording. After the owner moved the storage
root, the backlog must not be uploaded to the old root: nothing is delivered, the local folder stays, and
one log line per folder (not per pass) says why. A folder inside the current root is delivered as before.
Real asyncssh SFTP server on loopback, temporary directories only.

Run: venv/bin/python tests/test_vod_sweep_root.py
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_vod_sweep import Logs, Patched, Remote, SweepDb, REMOTE, run, server, session  # noqa: E402

DEADLINE = 90


class MovedDb(SweepDb):
    """The owner's storage root is now NEW_ROOT, not the one the sidecar was written under."""

    def __init__(self, remote, root):
        super().__init__(remote)
        self.root = root

    async def get_vod_storage(self, uid):
        storage = await super().get_vod_storage(uid)
        storage["remote_path"] = self.root
        return storage


def _passes(root, remote_dir, passes=1):
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodroot_") as t:
            async with Remote(t) as remote:
                d = session(t, "1_2026-01-01_5", {"chunk_000.mkv": b"data"}, remote=remote_dir)
                with Patched(t, remote, MovedDb(remote, root)), Logs() as logs:
                    for _ in range(passes):
                        await server.recover_vod_staging()
                tree = []
                for base, _dirs, files in os.walk(remote.root):
                    tree.extend(os.path.join(base, f) for f in files)
                return tree, d.exists(), (d / "chunk_000.mkv").exists() if d.exists() else False, logs.text()
    return asyncio.run(asyncio.wait_for(go(), DEADLINE))


def test_a_folder_outside_the_current_root_is_kept_and_nothing_is_uploaded():
    tree, folder, chunk, log = _passes("/moved", REMOTE, passes=3)
    assert tree == [], f"something was uploaded: {tree}"
    assert folder and chunk, "the local folder and its chunk must stay"
    lines = [l for l in log.split("\n") if "outside" in l and "1_2026-01-01_5" in l]
    assert len(lines) == 1, f"one line per folder, not per pass: {lines}"


def test_a_sibling_with_the_same_prefix_is_outside_and_dots_are_resolved():
    for root, rdir in (("/v/s", "/v/s2/2026-01-01"), ("/v/s", "/v/s/../x/2026-01-01"), ("/v", "/vv/a/b")):
        tree, folder, chunk, _log = _passes(root, rdir)
        assert tree == [] and folder and chunk, (root, rdir, tree)


def test_a_folder_inside_the_current_root_is_delivered_as_before():
    for root in ("/v", "/v/", "/v/./s", "/"):
        tree, folder, _chunk, _log = _passes(root, REMOTE)
        assert len(tree) == 1 and tree[0].endswith("chunk_000.mkv") and not folder, (root, tree, folder)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except BaseException as e:  # noqa: BLE001
                failed += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {e!r}")
    sys.exit(1 if failed else 0)
