"""Smoke check: voice setup panel (device picker, VAD gate, level meter,
loopback test, output device, PTT release delay).

The feature is client-side only, so this proves what can be proven without a
browser or a microphone:
  - the chat page and the watch page are served with voice.js v13, the chat
    page carries the settings window (meter and threshold line, PTT delay,
    input and output pickers, loopback box with a headphones warning, output
    picker hidden until the script finds support) and voice.js is served as
    JavaScript;
  - the served voice.js passes the Node harness of tests/test_voicesetup.py
    (fake microphones, senders, AudioContexts, timers, localStorage): the stored
    device is used on the next join, the VAD gate closes the sent track while
    silent and keeps the hang time, a 300 ms PTT delay keeps the end of words,
    the meter moves, a device switch keeps peers, the resume token and the
    gain nodes, the microphone is released when the panel closes, the loopback
    is off by default and refused in a call, the output picker needs
    AudioContext.setSinkId, saved settings are read before the chat socket opens,
    a second Join click or a device change during the microphone prompt opens no
    second microphone, the push-to-talk key works with a button focused unless it
    is Space or Enter, and a strict saved threshold gets a one-time notice;
  - the server is unchanged by it: a call over real WebSockets (join, speaking,
    leave) answers with the same payload, and device, threshold, delay and
    loopback fields that a client might add are neither stored nor sent on to
    other members.
Left to a manual check with a real browser: a USB microphone is used on the next
join, "no packets while silent" (chrome://webrtc-internals, outbound-rtp
packetsSent; a disabled track may still send keep-alive packets), the meter and
the threshold line on a real microphone, the loopback test with headphones, the
output picker in Chrome and its absence in Firefox and Safari.
"""
import asyncio
import json
import shutil
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path

PW = "Voicesetup-check-pw-1"
NAMES = ("vsalice", "vsbob")
HARNESS = Path(__file__).resolve().parents[2] / "tests" / "voicesetup_harness.js"

SETUP = r'''
import asyncio, json
from database import db
from auth import hash_password

async def main():
    await db.connect()
    try:
        out = {}
        for name in %(names)r:
            u = await db.get_user_by_username(name)
            out[name] = u["id"] if u else await db.create_user(name, hash_password(%(pw)r))
        print(json.dumps(out))
    finally:
        await db.close()

asyncio.run(main())
''' % {"names": NAMES, "pw": PW}


async def _pump(ws, events):
    try:
        async for msg in ws:
            if msg.type == 1:  # TEXT
                events.append(json.loads(msg.data))
    except Exception:
        pass


class Conn:
    def __init__(self, ws):
        self.ws = ws
        self.events = []
        self.task = asyncio.create_task(_pump(ws, self.events))

    async def send(self, **kw):
        await self.ws.send_json(kw)

    async def wait(self, pred, timeout=10.0, start=0):
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            for e in self.events[start:]:
                if pred(e):
                    return e
            await asyncio.sleep(0.05)
        return None

    async def close(self):
        await self.ws.close()
        self.task.cancel()


def _t(name):
    return lambda e: e.get("type") == name


async def run(ctx):
    def ok(name, passed, detail=""):
        ctx.ok(name, bool(passed), "" if passed else detail)

    rc, out = await ctx.run_py(SETUP)
    try:
        ids = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        ids = None
    ok("voicesetup: test users created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    alice, bob = ids["vsalice"], ids["vsbob"]

    async with AsyncExitStack() as stack:
        sessions = {}
        for name in NAMES:
            s = await stack.enter_async_context(ctx.http())
            r = await ctx.login(s, name, PW)
            sessions[name] = s if r.status == 200 else None
        ok("voicesetup: users can log in", all(sessions.values()))
        if not all(sessions.values()):
            return
        s_alice, s_bob = sessions["vsalice"], sessions["vsbob"]

        # ---- pages and script as served --------------------------------------------
        bodies = {}
        for label, url in (("chat page", "/chat"), ("watch page", "/watch/1")):
            async with s_alice.get(ctx.base_url + url) as r:
                bodies[label] = await r.text()
                status = r.status
            ok(f"voicesetup: the {label} loads", status == 200, f"status {status}")
            ok(f"voicesetup: the {label} loads voice.js v13",
               "/static/js/voice.js?v=13" in bodies[label] and "voice.js?v=12" not in bodies[label], "")
        chat = bodies["chat page"]
        ok("voicesetup: the chat page has the level meter with a threshold line",
           'id="voice-meter"' in chat and 'id="voice-meter-line"' in chat, "")
        ok("voicesetup: the chat page has the PTT delay slider (0 to 1000 ms)",
           'id="ptt-delay-slider"' in chat and 'max="1000"' in chat, "")
        ok("voicesetup: the chat page has the input picker and an output picker that starts hidden",
           'id="voice-input-device"' in chat and 'id="voice-output-device"' in chat
           and 'id="voice-output-settings" style="display:none;"' in chat, "")
        ok("voicesetup: the loopback test is unchecked and warns about headphones",
           'id="voice-loopback"' in chat and "headphones" in chat.lower()
           and "checked" not in chat.split('id="voice-loopback"')[1].split(">")[0], "")
        open_fn = chat.split("function openVoiceSettings")[1].split("function closeVoiceSettings")[0] if "function openVoiceSettings" in chat else ""
        ok("voicesetup: the chat page has a place for the one-time threshold notice, outside the VAD block, and shows it as text",
           'id="voice-gate-notice"' in chat and chat.index('id="voice-gate-notice"') < chat.index('id="vad-settings"')
           and "VoiceChat.takeGateNotice()" in open_fn and "gateEl.textContent = gateNotice" in open_fn, "")
        async with s_alice.get(f"{ctx.base_url}/static/js/voice.js?v=13") as r:
            script = await r.text()
            ctype = r.headers.get("Content-Type", "")
            status = r.status
        ok("voicesetup: voice.js v13 is served as JavaScript", status == 200 and "javascript" in ctype, f"{status} {ctype}")
        ok("voicesetup: the served script has the setup API and no markup injection",
           all(n in script for n in ("setInputDevice", "startMeter", "setLoopback", "setPttDelay", "listDevices"))
           and "innerHTML" not in script, "")

        # ---- the served script, in the harness --------------------------------------
        node = shutil.which("node")
        if not node:
            ctx.skip("voicesetup: gate, delay, meter, switch and output behaviour", "node is not installed")
        elif not HARNESS.exists():
            ctx.skip("voicesetup: gate, delay, meter, switch and output behaviour", f"{HARNESS} not found")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                served = Path(tmp) / "voice.js"
                served.write_text(script)
                proc = await asyncio.create_subprocess_exec(
                    node, str(HARNESS), str(served),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                raw, _ = await asyncio.wait_for(proc.communicate(), 90)
            rows = []
            for line in raw.decode("utf-8", "replace").splitlines():
                if line.startswith("RESULT "):
                    rows.append(json.loads(line[7:]))
            bad = [r for r in rows if not r["ok"]]
            ok(f"voicesetup: the served voice.js passes {len(rows)} behaviour checks under Node",
               rows and not bad and len(rows) >= 120,
               "; ".join(f"{r['name']}: {r['detail'][:80]}" for r in bad[:5]) or raw.decode()[-200:])

        # ---- the server is unchanged --------------------------------------------------
        async def connect(session, channel="general"):
            c = Conn(await session.ws_connect(f"{ctx.base_url}/ws/chat"))
            await c.send(type="join", channel=channel)
            await c.wait(_t("users"))
            return c

        ca = await connect(s_alice)
        cb = await connect(s_bob)
        try:
            # A client that wrongly added setup fields must not see them stored or relayed
            extra = dict(deviceId="vs-usb-mic-9f3", inputDeviceId="vs-usb-mic-9f3", outputDeviceId="vs-spk-77",
                         vadThreshold=-42, pttDelay=300, loopback=True)
            mark_b = len(cb.events)
            await ca.send(type="voice_join", **extra)
            vs_a = await ca.wait(_t("voice_state"))
            ok("voicesetup: a voice join still answers with voice_state and a resume token",
               bool(vs_a) and bool(vs_a.get("resume_token")), json.dumps(ca.events[-3:])[:300])
            await cb.send(type="voice_join")
            vs_b = await cb.wait(_t("voice_state"))
            joined = await ca.wait(lambda e: e.get("type") == "voice_user_joined" and e.get("user_id") == bob)
            ok("voicesetup: the second member joins and the first is told", bool(vs_b) and bool(joined), "")
            await ca.send(type="voice_speaking", speaking=True, **extra)
            speaking = await cb.wait(lambda e: e.get("type") == "voice_speaking_changed" and e.get("user_id") == alice)
            ok("voicesetup: the speaking state reaches the other member", bool(speaking), json.dumps(cb.events[-3:])[:300])
            wire = json.dumps(cb.events[mark_b:] + (vs_a and [vs_a] or []))
            ok("voicesetup: no setup field is stored or relayed to other members",
               not any(w in wire for w in ("vs-usb-mic-9f3", "vs-spk-77", "vadThreshold", "pttDelay", "loopback", "deviceId")),
               wire[:300])
            keys = {k for u in (vs_b or {}).get("users", []) for k in u}
            ok("voicesetup: the voice payload carries no device, threshold or delay field",
               keys <= {"user_id", "username", "muted", "deafened", "speaking", "screen_sharing", "reconnecting"}, str(sorted(keys)))
            await ca.send(type="voice_leave")
            await cb.send(type="voice_leave")
        finally:
            await ca.close()
            await cb.close()
