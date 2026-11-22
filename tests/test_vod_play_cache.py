"""VOD playback cache and helpers (vod_play.py): path rules, ffprobe verdict, the byte-capped LRU cache,
its reservations, and the start-up reconciliation of the folder with its index.

Pure filesystem work in a temporary folder, a few kilobytes. Run: venv/bin/python tests/test_vod_play_cache.py
"""
import asyncio
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import vod_play as vp  # noqa: E402
import vod_staging  # noqa: E402

vod_staging.TEMP_ROOTS = ()  # the sandboxes below live under /tmp


def test_url_paths_follow_the_listing_rules():
    ok = vp.chunk_path_from_url
    assert ok("Stream/2026-01-01/chunk_000.mkv.mp4") == "Stream/2026-01-01/chunk_000.mkv"
    assert ok("old.mkv.mp4") == "old.mkv"
    assert ok("Dir/UP.MKV.mp4") == "Dir/UP.MKV"
    for bad in ("", "x.mp4", "a/b.mkv", "../a/b.mkv.mp4", "a/../b.mkv.mp4", "/etc/x.mkv.mp4",
                "a//b.mkv.mp4", "a/./b.mkv.mp4", ".hidden/b.mkv.mp4", "a/.b.mkv.mp4", "a\\b.mkv.mp4",
                "a/b\x00.mkv.mp4", "a/b\n.mkv.mp4", "a/b.mp4.mp4", "a/" * 20 + "b.mkv.mp4",
                "x" * 2000 + ".mkv.mp4", "a/b.mkv.mp4/", None, 5):
        assert ok(bad) is None, bad


def test_setting_parsing():
    f = vp.cache_cap_bytes
    mb = 1024 * 1024
    assert f(None) == 512 * mb and f("") == 512 * mb and f("junk") == 512 * mb and f("-3") == 512 * mb
    assert f("nan") == 512 * mb and f("inf") == 512 * mb
    assert f("0") == 0 and f(0) == 0
    assert f("1.5") == int(1.5 * mb) and f("100") == 100 * mb


def test_verdict():
    def info(v="h264", a="aac", pix="yuv420p"):
        s = [{"codec_type": "video", "codec_name": v, "pix_fmt": pix}]
        if a:
            s.append({"codec_type": "audio", "codec_name": a})
        return {"streams": s}
    assert vp.verdict(info())[0]
    assert vp.verdict(info(a="mp3"))[0]
    assert vp.verdict(info(a=None))[0]
    ok, why = vp.verdict(info(a="opus"))
    assert not ok and "opus" in why
    assert not vp.verdict(info(v="hevc"))[0]
    assert not vp.verdict(info(pix="yuv420p10le"))[0]
    assert not vp.verdict({"streams": [{"codec_type": "audio", "codec_name": "aac"}]})[0]
    assert not vp.verdict({})[0] and not vp.verdict(None)[0]
    assert "Download" in vp.download_only_message("audio codec opus")


def test_ffmpeg_arguments_cannot_open_anything_but_the_given_file():
    argv = vp.remux_argv("/c/src.mkv", "/c/out.mp4", 1000)
    i = argv.index("-i")
    assert argv[argv.index("-f") + 1] == "matroska" and argv.index("-f") < i      # demuxer forced
    assert argv[argv.index("-protocol_whitelist") + 1] == "file" and argv.index("-protocol_whitelist") < i
    assert argv[i + 1] == "file:/c/src.mkv" and "+faststart" in argv and "-nostdin" in argv
    assert argv[argv.index("-c") + 1] == "copy" and argv[-1] == "file:/c/out.mp4" and "-fs" in argv
    assert "-c:v" not in argv and "libx264" not in argv
    probe = vp.ffprobe_argv("/c/src.mkv")
    assert "-protocol_whitelist" in probe and probe[probe.index("-f") + 1] == "matroska"
    assert vp.job_reserve(1000) > 1000 + vp.output_limit(1000) - 1


def test_keys_separate_owners_storage_and_remote_version():
    base = vp.entry_key(1, "aa", "p.mkv", 10, 5)
    assert base == vp.entry_key(1, "aa", "p.mkv", 10, 5)
    for other in (vp.entry_key(2, "aa", "p.mkv", 10, 5), vp.entry_key(1, "bb", "p.mkv", 10, 5),
                  vp.entry_key(1, "aa", "q.mkv", 10, 5), vp.entry_key(1, "aa", "p.mkv", 11, 5),
                  vp.entry_key(1, "aa", "p.mkv", 10, 6)):
        assert other != base
    a = vp.storage_ident({"host": "h", "port": 22, "username": "u", "remote_path": "/v/"})
    assert a == vp.storage_ident({"host": "h", "port": None, "username": "u", "remote_path": "/v"})
    assert a != vp.storage_ident({"host": "h", "port": 2222, "username": "u", "remote_path": "/v"})


def _cache(t):
    root = os.path.join(t, "cache")
    vp.prepare_dir(root)
    return vp.PlayCache(root)


def _make(cache, name, size):
    p = os.path.join(cache.new_work_dir(), name)
    Path(p).write_bytes(b"x" * size)
    return p


def _meta(owner=1, ident="aa", path="p.mkv", rsize=1, rmtime=1):
    return {"owner": owner, "ident": ident, "path": path, "rsize": rsize, "rmtime": rmtime}


def test_folder_is_private_and_refuses_foreign_folders():
    with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
        c = _cache(t)
        assert stat.S_IMODE(os.stat(c.root).st_mode) == 0o700
        foreign = os.path.join(t, "foreign")
        os.mkdir(foreign)
        Path(foreign, "precious.txt").write_text("x")
        try:
            vp.prepare_dir(foreign)
            raise AssertionError("a folder with foreign files must be refused")
        except ValueError:
            pass
        assert Path(foreign, "precious.txt").exists()
        link = os.path.join(t, "link")
        os.symlink(c.root, link)
        assert vp.refusal_reason(link) is not None
        assert vp.refusal_reason("/") is not None and vp.refusal_reason(os.path.expanduser("~")) is not None


def test_cache_folder_overlapping_staging_or_recordings_is_refused_even_as_the_own_default():
    with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
        root = os.path.join(t, "portal")
        own = os.path.join(root, "data", "vod_play_cache")
        os.makedirs(own)
        Path(own, "unmarked.txt").write_text("x")        # the own default is accepted unmarked and non-empty
        assert vp.refusal_reason(own, root) is None
        assert vp.refusal_reason(own, root, (), (os.path.join(root, "data", "vod_tmp"), os.path.join(root, "recordings"))) is None
        for other in (own, os.path.join(own, "staging"), os.path.join(root, "data"), root):
            reason = vp.refusal_reason(own, root, (), (other,))
            assert reason and "overlaps" in reason, (other, reason)
        # a marked folder somewhere else: staging inside it, equal to it, or around it
        folder = os.path.join(t, "cache")
        vp.prepare_dir(folder)
        for other in (folder, os.path.join(folder, "sub"), t):
            assert vp.refusal_reason(folder, None, (), (other,)), other
            try:
                vp.prepare_dir(folder, None, (), (other,))
                raise AssertionError("prepare_dir must refuse an overlapping folder")
            except ValueError:
                pass
        assert vp.refusal_reason(folder, None, (), (os.path.join(t, "cache2"), "", None)) is None


def test_entries_are_0600_and_lru_evicts_the_oldest_to_fit():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
            c = _cache(t)
            cap = 1000
            for i, name in enumerate(("a", "b", "c")):
                key = vp.entry_key(1, "aa", name, 300, 1)
                assert c.try_reserve(300, cap)
                assert c.add(key, _make(c, "o.mp4", 300), _meta(path=name), 300)
                assert stat.S_IMODE(os.stat(os.path.join(c.root, key + ".mp4")).st_mode) == 0o600
                c.entries[key]["used"] = 100 + i          # a < b < c in recency
            assert c.used_bytes() == 900 and len(c.entries) == 3
            kb = vp.entry_key(1, "aa", "b", 300, 1)
            assert c.get(kb)                                # b is now the most recent
            assert c.try_reserve(300, cap)                  # needs room: a goes first
            ka = vp.entry_key(1, "aa", "a", 300, 1)
            kc = vp.entry_key(1, "aa", "c", 300, 1)
            assert ka not in c.entries and kb in c.entries and kc in c.entries
            assert not os.path.exists(os.path.join(c.root, ka + ".mp4"))
            assert c.used_bytes() <= cap and c.disk_bytes() <= cap + 1000
            c.release(300)
            assert not c.try_reserve(cap + 1, cap)           # can never fit
            assert not await c.reserve(cap + 1, cap, 0.1)
    asyncio.run(go())


def test_the_cap_counts_stored_copies_and_a_reservation_is_working_space_only():
    async def go():
        with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
            c = _cache(t)
            cap = 1000
            # a job that works on 800 + 800 bytes and will store up to 800: allowed, the cap is about the copy
            assert c.try_reserve(1600, cap, 800)
            assert c.reserved == 1600
            # a second one is not made to wait for the first: its working space is bounded elsewhere
            assert await c.reserve(1600, cap, 0.2, 800)
            c.release(3200)
            assert c.reserved == 0
            # only a copy that alone exceeds the cap is refused
            assert not c.try_reserve(1600, cap, 1001) and c.reserved == 0
            assert not await c.reserve(1600, cap, 0.2, 1001)
            # room for the copy is made by evicting the least recently used copies, never by refusing
            for i, name in enumerate("ab"):
                k = vp.entry_key(1, "aa", name, 400, 1)
                c.add(k, _make(c, "o.mp4", 400), _meta(path=name), 0)
                c.entries[k]["used"] = 10 + i
            assert c.used_bytes() == 800
            assert c.try_reserve(1000, cap, 500)
            assert c.used_bytes() <= 500 and vp.entry_key(1, "aa", "b", 400, 1) in c.entries
            c.release(1000)
            # reserving ahead never evicts
            assert not c.try_reserve_free(1000, cap, 700) and c.used_bytes() == 400
            assert c.try_reserve_free(1000, cap, 600) and c.reserved == 1000
    asyncio.run(go())


def test_reconcile_drops_missing_and_removes_strays_and_keeps_the_rest():
    with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
        c = _cache(t)
        k1, k2, k3 = (vp.entry_key(1, "aa", n, 10, 1) for n in "xyz")
        for k, n in ((k1, "x"), (k2, "y"), (k3, "z")):
            c.try_reserve(10, 10 ** 6)
            c.add(k, _make(c, "o.mp4", 10), _meta(path=n), 10)
        os.unlink(os.path.join(c.root, k2 + ".mp4"))                 # file gone
        Path(c.root, k3 + ".mp4").write_bytes(b"short")              # size changed
        stray = "0" * 32 + ".mp4"
        Path(c.root, stray).write_bytes(b"stray")
        Path(c.root, "index.json.tmp").write_text("{}")
        Path(c.work_root(), "job-1").mkdir(parents=True, exist_ok=True)
        Path(c.work_root(), "job-1", "src.mkv").write_bytes(b"half")
        Path(c.root, "notes.txt").write_text("not ours")
        fresh = vp.PlayCache(c.root)
        stats = fresh.reconcile()
        assert set(fresh.entries) == {k1}, fresh.entries.keys()
        assert stats["kept"] == 1 and stats["dropped"] == 2 and stats["strays"] >= 3
        names = set(os.listdir(c.root))
        assert stray not in names and "index.json.tmp" not in names and k3 + ".mp4" not in names
        assert "notes.txt" in names and k1 + ".mp4" in names
        assert os.listdir(c.work_root()) == []
        again = vp.PlayCache(c.root)
        again.reconcile()
        assert set(again.entries) == {k1}                            # the index file survived
        assert stat.S_IMODE(os.stat(os.path.join(c.root, "index.json")).st_mode) == 0o600
        Path(c.root, "index.json").write_text("{not json")
        broken = vp.PlayCache(c.root)
        broken.reconcile()
        assert broken.entries == {} and not os.path.exists(os.path.join(c.root, k1 + ".mp4"))


def test_purge_by_owner_and_by_storage():
    with tempfile.TemporaryDirectory(prefix="vodplay_") as t:
        c = _cache(t)
        keys = {}
        for owner, ident in ((1, "aa"), (1, "bb"), (2, "aa")):
            k = vp.entry_key(owner, ident, "p.mkv", 5, 1)
            keys[(owner, ident)] = k
            c.try_reserve(5, 1000)
            c.add(k, _make(c, "o.mp4", 5), _meta(owner=owner, ident=ident), 5)
        assert c.purge(owner=1, ident_not="aa") == 1            # storage changed: only the old one goes
        assert keys[(1, "bb")] not in c.entries and keys[(1, "aa")] in c.entries
        assert c.purge(owner=1) == 1 and set(c.entries) == {keys[(2, "aa")]}
        assert c.owners() == {2: {"aa"}}
        assert c.purge() == 1 and c.disk_bytes() <= 200      # only the index and marker remain


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except BaseException as e:  # noqa: BLE001
                fails += 1
                import traceback
                traceback.print_exc()
                print(f"FAIL {name}: {e}")
    print("FAILED" if fails else "all passed")
    sys.exit(1 if fails else 0)
