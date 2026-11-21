"""Smoke check: voice connection-quality bars and the lost-audio hint (client only).

Proves what can be proven without a browser or a microphone:
  - the chat page and the watch page are served with voice.js v15 and the bar styles;
  - the served voice.js passes the same Node harness as tests/test_voicequality.py
    (fake peer connections with scripted getStats, a controllable clock, page
    visibility): rising loss drops the bars within an interval and the tooltip
    shows the loss, a muted peer never shows the hint, the loop stops on leave
    and while the page is hidden, nothing from the stats reaches the server or the page;
  - no server change: the check sends nothing and reads nothing from the database.
Uses one random-suffix account and needs no admin password.
Left to a manual check on real devices: real getStats shapes (Chrome, Firefox,
Safari), whether an idle VAD or PTT peer still sends packets (decides whether the
6 second hint ever fires by mistake), the look of the bars on a phone.
"""
import asyncio
import json
import secrets
import shutil
import tempfile
from pathlib import Path

PW = "Voicequality-check-pw-1"
HARNESS = Path(__file__).resolve().parents[2] / "tests" / "voicequality_harness.js"

SETUP = r'''
import asyncio, json
from database import db
from auth import hash_password

async def main():
    await db.connect()
    try:
        print(json.dumps({"id": await db.create_user(%(name)r, hash_password(%(pw)r))}))
    finally:
        await db.close()

asyncio.run(main())
'''


async def run(ctx):
    def ok(name, passed, detail=""):
        ctx.ok(name, bool(passed), "" if passed else detail)

    name = "vq" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"name": name, "pw": PW})
    try:
        uid = json.loads(out.strip().splitlines()[-1])["id"]
    except (ValueError, IndexError, KeyError):
        uid = None
    ok("voicequality: test user created", rc == 0 and bool(uid), out[-300:])
    if not uid:
        return
    async with ctx.http() as s:
        r = await ctx.login(s, name, PW)
        ok("voicequality: the user can log in", r.status == 200, f"status {r.status}")
        if r.status != 200:
            return
        for label, url in (("chat page", "/chat"), ("watch page", "/watch/1")):
            async with s.get(ctx.base_url + url) as resp:
                body = await resp.text()
                status = resp.status
            ok(f"voicequality: the {label} loads", status == 200, f"status {status}")
            ok(f"voicequality: the {label} loads voice.js v15 with the bar styles",
               "/static/js/voice.js?v=15" in body and "voice.js?v=14" not in body
               and ".vq-bar" in body and ".vq-noaudio .vq-hint" in body, "")
        async with s.get(f"{ctx.base_url}/static/js/voice.js?v=15") as resp:
            script = await resp.text()
            ctype = resp.headers.get("Content-Type", "")
            status = resp.status
        ok("voicequality: voice.js v15 is served as JavaScript", status == 200 and "javascript" in ctype, f"{status} {ctype}")
        ok("voicequality: the served script has the scoring and no markup injection",
           "scoreQuality" in script and "readQualityStats" in script and "innerHTML" not in script, "")

    node = shutil.which("node")
    if not node:
        ctx.skip("voicequality: bars, hint and loop behaviour", "node is not installed")
    elif not HARNESS.exists():
        ctx.skip("voicequality: bars, hint and loop behaviour", f"{HARNESS} not found")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            served = Path(tmp) / "voice.js"
            served.write_text(script)
            proc = await asyncio.create_subprocess_exec(
                node, str(HARNESS), str(served),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            raw, _ = await asyncio.wait_for(proc.communicate(), 60)
        rows = [json.loads(l[7:]) for l in raw.decode("utf-8", "replace").splitlines() if l.startswith("RESULT ")]
        bad = [r for r in rows if not r["ok"]]
        ok(f"voicequality: the served voice.js passes {len(rows)} behaviour checks under Node",
           rows and not bad and len(rows) >= 70,
           "; ".join(f"{r['name']}: {r['detail'][:80]}" for r in bad[:5]) or raw.decode()[-200:])
