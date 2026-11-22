"""The disk guard stops a recording by writing "q" to ffmpeg's stdin. This proves, with the
recorder's own output arguments (vod_staging.segment_args), that this leaves a final chunk that
ffprobe accepts and that decodes to its end, and that the fallback ladder works when ffmpeg
ignores "q".

The input is a short generated clip read at its own speed and looped, standing in for the
stream. That is NOT the RTSPS input the recorder really uses (-rtsp_transport tcp is an input
option of its own); what is proven is the segment muxer side: the chunk that is open when "q"
arrives is closed properly.

Run: venv/bin/python tests/test_vod_guard_stop.py
Writes well under a megabyte, inside a temporary directory, and leaves no process behind.
"""
import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import vod_staging as vs  # noqa: E402


def make_clip(path):
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10",
         "-f", "lavfi", "-i", "sine=frequency=440", "-t", "6", "-c:v", "libx264", "-preset", "ultrafast",
         "-g", "10", "-c:a", "aac", "-b:a", "32k", str(path)],
        check=True, timeout=60)


def probe_duration(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0",
                        str(path)], capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def decode_all(path):
    """Decode the whole file to nothing; return (stderr, seconds decoded)."""
    r = subprocess.run(["ffmpeg", "-v", "error", "-i", str(path), "-f", "null", "-progress", "pipe:1", "-"],
                       capture_output=True, text=True, timeout=60)
    seconds = 0.0
    for line in r.stdout.splitlines():
        if line.startswith("out_time_us="):
            try:
                seconds = int(line.split("=")[1]) / 1e6
            except ValueError:
                pass
    return r.returncode, r.stderr.strip(), seconds


def children_of_this_process():
    me = os.getpid()
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fh:
                parts = fh.read().rsplit(")", 1)[1].split()
            if int(parts[1]) == me and parts[0] != "Z":
                out.append(int(entry))
        except (OSError, IndexError, ValueError):
            continue
    return out


def check_chunks(session_dir, expect_min):
    chunks = vs.chunk_files(session_dir)
    assert len(chunks) >= expect_min, chunks
    for c in chunks:
        rc, dur, err = probe_duration(c)
        assert rc == 0 and not err and dur not in ("", "N/A"), (c, rc, dur, err)
        rc2, err2, decoded = decode_all(c)
        assert rc2 == 0 and err2 == "", (c, rc2, err2)
        # it plays to its end: what decodes is what the container says it holds
        assert abs(decoded - float(dur)) < 0.5, (c, decoded, dur)
    return chunks


async def record_then_stop(clip, session_dir, segment_seconds, run_seconds, server, stop=None):
    cmd = (["ffmpeg", "-y", "-re", "-stream_loop", "-1", "-i", str(clip)]
           + vs.segment_args(session_dir, 0, segment_seconds))
    process = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        await asyncio.sleep(run_seconds)
        assert process.returncode is None, "the recording ended on its own"
        started = asyncio.get_event_loop().time()
        how = await (stop or server._vod_graceful_stop)(process)
        return how, process.returncode, asyncio.get_event_loop().time() - started
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


def test_q_leaves_valid_final_chunks():
    import server
    with tempfile.TemporaryDirectory(prefix="vodstop_") as t:
        clip = Path(t) / "src.mp4"
        make_clip(clip)
        # a real-length segment: the only chunk is the one that is open when "q" arrives
        d1 = os.path.join(t, "long")
        os.mkdir(d1)
        how, rc, took = asyncio.run(record_then_stop(clip, d1, 300, 4.5, server))
        assert how == "q" and rc == 0 and took < 5, (how, rc, took)
        assert len(check_chunks(d1, 1)) == 1
        # short segments: several complete chunks plus the one that "q" closes
        d2 = os.path.join(t, "short")
        os.mkdir(d2)
        how, rc, took = asyncio.run(record_then_stop(clip, d2, 2, 7.3, server))
        assert how == "q" and rc == 0 and took < 5, (how, rc, took)
        check_chunks(d2, 3)
    assert children_of_this_process() == [], children_of_this_process()


def test_fallback_when_ffmpeg_ignores_q():
    """A process that never reads stdin is ended by the signal ladder, within bounded time."""
    import server
    old = server.VOD_STOP_Q_WAIT
    server.VOD_STOP_Q_WAIT = 0.5

    async def go():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "import time\ntime.sleep(60)",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.sleep(0.3)
            return await server._vod_graceful_stop(proc), proc.returncode
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    try:
        how, rc = asyncio.run(go())
    finally:
        server.VOD_STOP_Q_WAIT = old
    assert how in ("sigint", "terminate", "kill") and rc is not None and rc != 0, (how, rc)
    assert children_of_this_process() == []


def test_stop_of_a_finished_process_does_not_fail():
    import server

    async def go():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "pass", stdin=asyncio.subprocess.PIPE)
        await proc.wait()
        first = await server._vod_graceful_stop(proc)
        return first

    assert asyncio.run(go()) == "exited"


def test_recorder_uses_the_shared_output_arguments_and_a_stdin_pipe():
    src = (ROOT / "server.py").read_text()
    start = src.index("async def start_vod_recording")
    body = src[start:start + 9000]
    assert "vod_staging.segment_args(session_dir, start_number, VOD_SEGMENT_DURATION)" in body
    assert "stdin=asyncio.subprocess.PIPE" in body
    assert "-segment_format" not in body, "the output arguments must come from vod_staging.segment_args"
    args = vs.segment_args("/x", 7, 300)
    assert args[-1] == "/x/chunk_%03d.mkv" and "-segment_start_number" in args and "7" in args


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
