#!/usr/bin/env python3
"""Take the README screenshots from a staged demo instance.

This starts its own throwaway copy of the portal (the staging helpers of
tools/stage_smoke.py: a copy of the source tree in a private temp directory, a
fresh database, PORTAL_STAGE_MODE, a self-signed certificate, its own port),
fills it with fictional demo data through the real HTTP API and the chat
WebSocket, and drives a headless Chromium over it to write PNG files into
docs/screenshots/.

It refuses to run against anything it did not start itself: there is no option
for a URL, and the instance is only used after its /health answer was checked
against the certificate this script generated. Never run it against production,
and never point it at a copy of a real database: the demo data is the only
thing that may appear in a picture.

Needs the project's requirements (aiohttp and friends) plus playwright and
Pillow in ONE virtual environment that is not the production one. Playwright is
deliberately not in requirements.txt:

    python3 -m venv /path/to/shots-venv
    /path/to/shots-venv/bin/pip install -r requirements.txt playwright pillow
    /path/to/shots-venv/bin/python tools/make_screenshots.py --chromium /usr/bin/chromium

The system Chromium is driven through executable_path; no browser download is
needed. The portal is reached as https://portal.example.org:<port> (a host
resolver rule maps that name to 127.0.0.1 inside the browser only), so every
link the portal builds shows the example name.

Pictures of 1.18.0 (share-expiry, api-keys, admin-signin-limits) need no extra setup: their
demo data (shares with end times, three administrator keys) is seeded with the rest.

Pictures of 1.19.0 (chat-notify-menu, phone-notifications, admin-push) need no extra setup either. The demo data
holds a notification level for one member, and push devices of three members whose endpoints are made-up
https://push.example.org addresses with freshly generated throw-away keys; push.example.org is added to the
allowed push hosts of the staged instance through the real admin route. Nothing is ever sent to a push service
(the staged instance only drops such an endpoint) and the test-push button is never pressed. The browser is only
granted the notification permission; it does not subscribe.

Pictures of 1.20.0 (admin-recordings, chat-prune, chat-retention, voice-moderation) need no extra setup. The demo
data holds four session recordings of the demo members: made-up shell output on a made-up host (example-host, a
user called demo, the documentation address 192.0.2.50, a token that says it is not a secret), written as plain
asciicast files with mode 0600 into the staged instance's own recordings folder, with rows in its own database.
The recording that is played in the Recordings picture is seeded; nothing is recorded from this machine. The prune
and retention pictures open the dialogs of the general channel as the administrator, count the messages of a range
(a dry run) and type a value into a retention field; nothing is saved and nothing is removed. voice-moderation
joins two demo members to one voice room in two headless browsers with Chromium's fake microphone, an empty list
of ICE servers (so nothing is dialled outside the machine) and the real getStats readings. Every one of these
pictures is checked for the host name, user name and home directory of this machine and for the temporary
directory of the staged instance before it is written.

Pictures of 1.21.0 (my-vods, my-vods-notice, vod-player, admin-vod-settings) need no extra setup. The staged
instance cannot dial a storage on loopback (its outbound host policy stays on), so the browser session of the
picture answers the VOD routes itself (Playwright route handlers, like the health call below) with made-up
data: a list of chunks of a made-up stream on a made-up storage, the notice text the disk guard writes for a
stopped recording, and a short synthetic test pattern (ffmpeg testsrc2, H.264 with AAC, index first) for the
player. The pages, scripts and styles are the portal's own. The player picture waits until the browser
really decodes a frame and says so when it cannot (a Chromium without H.264 then shows the page without a
frame; nothing is painted in). hls.js is not loaded (the request to its host is dropped, so nothing leaves the
machine). The admin picture is the four VOD fields of the Data Retention card, read from
the staged instance's own settings.

Pictures of 1.22.0 (dashboard-organise, dashboard-organise-dialog, announcement-banner, maintenance-page,
upstream-error-page, block-page, admin-block-lookup, admin-maintenance, admin-announcements) need no extra setup
either; each makes what it shows through the portal's own routes inside its picture and removes it afterwards (the
announcement, the maintenance flag and the shared connection of the maintenance picture), so no later picture
carries a banner or a flag. The status dots of dashboard-organise are the feature's own state: the staged instance
probes nothing except a literal 127.0.0.1 target whose port is in its stage-only setting, so three demo
connections are pointed at 127.0.0.1 in the stage's own database, one port has a listener of this script (up) and
one port has none (down), the checks are switched on through the stage's settings, and the picture is taken once
the real status route answers up and down. The cards would then show 127.0.0.1 and a random port, so the browser
session of that picture rewrites the host and port of those three cards (and only these) in the list answer to
the fictional names they were created with; the dots, their tooltips and everything else are what the portal
answered. The checks are switched off again after the picture. The upstream error page is the one a member
gets for /search/ while the search service is not running (nothing is dialled). The block page is the one a client
at the already blocked documentation address 198.51.100.77 gets; the reference is read from that page and typed into
the administrator's Reference lookup. Unblock is never pressed.

Pictures of 1.23.0 (watch-schedule, streams-upcoming, schedule-editor, calendar-link, chat-message-menu, saved-view)
need no extra setup. Each makes its data through the portal's own routes inside its picture, once per run: the
schedule entries of the demo streams (sam's offline stream gets a weekly slot, river and jordan one slot each,
alex two slots of his own stream, and alex marks river's slot Interested), alex's calendar link (the picture is
taken after a reload, so it shows the state the portal keeps, "You have a calendar link", and no token or address
at all), and three saved messages of alex (one of them a message he posts and deletes through the chat's own
frames, so the Saved view shows it as no longer available; one with a reminder tomorrow at 9:00). Times are made
from the real clock when the picture is taken, so the dates in the pictures are the dates of that day. The new
shots are defined last, so a full run takes them after the older pictures, which therefore carry no schedule.
Every one of them is checked for the host name, user name and home directory of this machine and for the
temporary directory of the staged instance before it is written.

Options: --only name,name  take only these pictures (the demo data is still
seeded), --list  print the picture names, --port, --out, --no-optimize.

Pictures that would show this machine's own data are not taken: the device
metrics section is never opened, and the admin browser session answers the
host health call (load, memory, disk, uptime, connection counts) and the free
space shown on the backups card with made-up demo numbers, so no value of the
machine the script runs on reaches a picture.
"""

import argparse
import asyncio
import json
import shutil
import signal
import sys
import tempfile
import time
import traceback
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))
try:
    import aiohttp
    import stage_smoke as ss
except SystemExit:
    raise
except ImportError as e:  # pragma: no cover
    sys.exit(f"missing module ({e}): run this with the virtual environment described at the top of the file")

REPO = TOOLS_DIR.parent
DEMO_HOST = "portal.example.org"
DEFAULT_PORT = 8921
VIEWPORT = {"width": 1280, "height": 768}
PHONE = {"width": 390, "height": 844}

# Fictional demo people. The superadmin is the account `server.py init` creates;
# passwords are throwaway values of the staged database only.
PASSWORD = "Demo-pass-9157"
ADMIN_NAME = "admin"
PEOPLE = [
    # name, role, avatar colour, initials
    ("sam", "moderator", "#10b981", "SM"),
    ("alex", "user", "#3b82f6", "AL"),
    ("river", "user", "#f59e0b", "RV"),
    ("jordan", "user", "#ec4899", "JO"),
    ("casey", "user", "#8b5cf6", "CA"),
]


# The address each demo account appears to come from (documentation range 192.0.2.0/24).
ADDRESSES = {"admin": "192.0.2.10", "sam": "192.0.2.11", "alex": "192.0.2.12", "river": "192.0.2.13",
             "jordan": "192.0.2.14", "casey": "192.0.2.15"}
DESKTOP_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


class Fail(Exception):
    pass


# ---------------------------------------------------------------------------
# The staged instance
# ---------------------------------------------------------------------------

class Stage:
    """Starts the staged server; stops it and removes the temp dir on exit."""

    def __init__(self, port: int):
        self.port = port
        self.dir: Path | None = None
        self.server = None
        self.admin_password = None
        self.base = f"https://{DEMO_HOST}:{port}"
        self.direct = f"https://127.0.0.1:{port}"

    def start(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="portal-shots-")).resolve()
        self.dir.chmod(0o700)
        n = ss.stage_tree(REPO, self.dir)
        print(f"staged {n} files", flush=True)
        cert, key = ss.make_cert(self.dir)
        ss.write_env(self.dir, self.port, cert, key, None)
        env_path = self.dir / ".env"
        lines = [ln for ln in env_path.read_text().splitlines()
                 if not ln.startswith(("HOSTNAME=", "STREAM_HOSTNAME="))]
        # The loopback peer is trusted as a proxy so that the CF-Connecting-IP header decides which
        # address the portal records: every address in the data and in the pictures is a documentation one.
        lines = [ln for ln in lines if not ln.startswith("TRUSTED_PROXIES=")]
        lines += [f"HOSTNAME={DEMO_HOST}", f"STREAM_HOSTNAME={DEMO_HOST}", "TRUSTED_PROXIES=127.0.0.1"]
        env_path.write_text("\n".join(lines) + "\n")
        env = ss.child_env(self.dir)
        res = ss.subprocess.run([ss.PYTHON, "server.py", "init"], cwd=str(self.dir), env=env,
                                capture_output=True, text=True, timeout=120)
        creds = self.dir / "admin_credentials.txt"
        if res.returncode != 0 or not creds.exists():
            raise Fail("server.py init failed:\n" + (res.stdout + res.stderr)[-600:])
        for line in creds.read_text().splitlines():
            if line.startswith("Password:"):
                self.admin_password = line.split(":", 1)[1].strip()
        if not self.admin_password:
            raise Fail("no admin password in the init output")
        self.server = ss.StagedServer(self.dir, env, self.port, cert)
        self.server.start()
        self.server.wait_healthy()      # also proves the answering server holds our certificate
        print(f"staged server is up on 127.0.0.1:{self.port}", flush=True)

    def stop(self) -> None:
        if self.server is not None:
            self.server.stop()
            self.server = None
        if self.dir is not None:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class Client:
    """One logged-in member: HTTP session (cookie) against the staged server."""

    def __init__(self, stage: Stage, name: str):
        self.stage, self.name = stage, name
        self.http = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            headers={"CF-Connecting-IP": ADDRESSES.get(name, "192.0.2.99"), "User-Agent": DESKTOP_AGENT},
            timeout=aiohttp.ClientTimeout(total=60),
        )
        self.user_id = None

    async def login(self, password: str):
        r = await self.http.post(f"{self.stage.direct}/login", json={"username": self.name, "password": password})
        body = await r.json(content_type=None)
        if r.status != 200 or body.get("status") != "logged_in":
            raise Fail(f"login of {self.name} failed: {r.status} {body}")
        return body

    async def api(self, method: str, path: str, body=None, ok=(200, 201), headers=None):
        r = await self.http.request(method, f"{self.stage.direct}{path}", json=body, headers=headers)
        try:
            data = await r.json(content_type=None)
        except Exception:
            data = None
        if r.status not in ok:
            raise Fail(f"{method} {path} -> {r.status} {data}")
        return data

    async def close(self):
        await self.http.close()

    def cookies(self) -> list:
        """The session cookies as playwright cookie dicts for the demo host."""
        out = []
        for c in self.http.cookie_jar:
            out.append({"name": c.key, "value": c.value, "domain": DEMO_HOST, "path": "/",
                        "secure": True, "httpOnly": bool(c.get("httponly")), "sameSite": "Lax"})
        return out


class Chat:
    """A chat WebSocket of one member."""

    def __init__(self, client: Client):
        self.client = client
        self.ws = None
        self.frames: list = []
        self._reader = None
        self.channels: dict = {}

    async def open(self):
        self.ws = await self.client.http.ws_connect(f"{self.client.stage.direct}/ws/chat", max_msg_size=0)
        self._reader = asyncio.create_task(self._read())
        await asyncio.sleep(0.4)

    async def _read(self):
        try:
            async for m in self.ws:
                if m.type == aiohttp.WSMsgType.TEXT:
                    self.frames.append(json.loads(m.data))
        except Exception:
            pass

    async def send(self, **kw):
        await self.ws.send_json(kw)

    async def wait_for(self, typ: str, after: int = 0, timeout: float = 8.0, match=None):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for f in self.frames[after:]:
                if f.get("type") == typ and (match is None or match(f)):
                    return f
            await asyncio.sleep(0.05)
        raise Fail(f"{self.client.name}: no {typ!r} frame (last frames: {[f.get('type') for f in self.frames[-6:]]})")

    async def say(self, text: str, reply_to=None, pause: float = 0.35) -> int:
        mark = len(self.frames)
        kw = {"type": "message", "message": text}
        if reply_to:
            kw["reply_to"] = reply_to
        await self.send(**kw)
        f = await self.wait_for("message", mark, match=lambda f: f.get("message") == text or f.get("content") == text)
        await asyncio.sleep(pause)
        return f.get("id") or f.get("message_id")

    async def close(self):
        if self.ws is not None and not self.ws.closed:
            await self.ws.close()
        if self._reader:
            self._reader.cancel()


# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------

# Reaction characters are the ones the chat page's own picker offers.
THUMBS, TADA, HEART, FIRE, EYES, CHECK = "\U0001F44D", "\U0001F389", "\u2764\ufe0f", "\U0001F525", "\U0001F440", "\u2705"

# (author, text, extras). extras: {"reply": index of an earlier line of the same list,
# "react": [(emoji, [reactors])], "pin": True, "anon": True}
GENERAL = [
    ("sam", "Morning all. Reminder that the monthly maintenance window is this Saturday, 02:00 to 03:00 UTC.", {"pin": True}),
    ("alex", "Thanks sam. Is anything changing on our side?", {}),
    ("sam", "No, just OS updates on the relay host. Streams will drop for a few minutes at most.", {"reply": 1}),
    ("river", "Good to know. I will move my game night to Sunday then.", {"react": [(THUMBS, ["alex", "sam"])]}),
    ("jordan", "Has anyone tried the new voice setup window? The level meter is handy.", {}),
    ("casey", "Yes, the noise gate threshold fixed my fan noise problem completely.", {"reply": 4}),
    ("river", "What threshold did you end up with?", {}),
    ("casey", "Around minus 45 dB. Speak normally and watch where the bar peaks, then set it just above the idle level.", {}),
    ("jordan", "That worked for me too, thanks.", {"react": [(HEART, ["casey"])]}),
    ("alex", "Seed swap thread: I have too many tomato seedlings. Anyone want some?", {}),
    ("river", "Yes please! I can trade basil.", {"reply": 9}),
    ("alex", "Deal. I will bring them to the meetup.", {}),
    ("sam", "Speaking of the meetup, the date is set for the 14th at the community hall.", {}),
    ("casey", "Newcomer question from my neighbour.", {"react": [(TADA, ["sam", "alex", "river"])]}),
    ("jordan", "Great. I will make a short slide about how to join the portal for newcomers.", {}),
    ("sam", "Perfect, keep it simple: invite code, username, done.", {}),
    ("river", "Does the invite code change every day?", {}),
    ("sam", "The daily one does. Single-use codes for guests never expire until used.", {"reply": 16}),
    ("alex", "Good reminder, I always forget which kind I handed out.", {}),
    ("casey", "Here is the guide we followed last time: https://example.org/guides/first-meetup", {}),
    ("jordan", "Bookmarked. Anyone up for a quick call tonight to plan the schedule?", {}),
    ("river", "I am free after 8.", {}),
    ("alex", "Same here. Voice channel at 8:15?", {}),
    ("jordan", "Works for me.", {"react": [(CHECK, ["river", "alex"])]}),
    ("sam", "I will join if I can get the kids to bed in time.", {}),
    ("casey", "No rush, we will post notes afterwards.", {}),
    ("river", "Newcomer question from my neighbour: can she watch the stream without an account?", {}),
    ("sam", "Only if the stream owner switches on unauthenticated viewing for that stream. Otherwise she needs an account.", {"reply": 26}),
    ("river", "Got it, I will ask her to register.", {}),
    ("alex", "Print shop news: the new filament arrived, so the lamp project can continue.", {}),
    ("casey", "Nice! Photos when it is done please.", {}),
    ("alex", "Will do.", {"react": [(THUMBS, ["casey"])]}),
    ("jordan", "Weather looks good for the weekend hike. Who is in?", {}),
    ("river", "In!", {}),
    ("casey", "In, if my knee holds up.", {}),
    ("sam", "I am on duty Saturday but free Sunday.", {}),
    ("jordan", "Sunday it is then. Meeting point is the trailhead parking lot at 9.", {"react": [(FIRE, ["river"]), (THUMBS, ["casey", "sam"])]}),
    ("alex", "Bringing coffee in a thermos.", {}),
    ("river", "You are a hero.", {}),
    ("casey", "Someone remind me to charge the camera battery.", {}),
    ("sam", "Will do, I will ping you Saturday evening.", {}),
    ("jordan", "Quick poll coming up for the potluck menu.", {}),
    ("POLL", "Which dish should we plan for the potluck?", {
        "options": ["Vegetable lasagna", "Chili", "Roast potatoes", "Soup bar"],
        "author": "jordan", "votes": {"alex": 0, "river": 1, "casey": 0, "sam": 3}}),
    ("alex", "Voted. Lasagna is hard to beat.", {}),
    ("river", "Chili for the win, but I will eat anything.", {}),
    ("casey", "Posting anonymously: I would love more vegetarian options at the potluck, if that is OK.", {"anon": True}),
    ("sam", "Good point, noted for the menu.", {}),
    ("jordan", "Let us do the lasagna and a bean chili then.", {}),
    ("alex", "Perfect compromise.", {"react": [(HEART, ["sam", "river", "casey"])]}),
    ("river", "Does anyone have a recipe link for a good bean chili?", {}),
    ("casey", "This one is reliable: https://example.org/recipes/bean-chili", {}),
    ("river", "Thanks!", {}),
    ("sam", "Housekeeping: please keep stream chat friendly and on topic. Thanks everyone for being kind.", {}),
    ("alex", "Always.", {}),
    ("jordan", "Hey, does the file manager let me upload photos from the meetup?", {}),
    ("sam", "Chat accepts images and files up to the size limit, use the paperclip button.", {"reply": 54}),
    ("jordan", "Perfect, thank you.", {}),
    ("river", "Heading out for lunch, back in an hour.", {}),
    ("casey", "Enjoy!", {}),
    ("alex", "Anyone seen the new theme options? There are a lot of them now.", {}),
    ("sam", "Yes, top right, the palette button. I like the high contrast one for the projector.", {"reply": 59}),
    ("jordan", "Good idea, I will test it on the projector at the hall.", {}),
    ("casey", "Test it early, hall wifi can be slow.", {}),
    ("river", "I will bring a long HDMI cable too.", {"react": [(THUMBS, ["jordan"])]}),
    ("alex", "Okay, the lamp is printing. Fingers crossed.", {}),
    ("sam", "Looking forward to it.", {}),
    ("jordan", "Reminder: slides are due by Thursday evening.", {}),
    ("casey", "I will send mine tomorrow.", {}),
    ("river", "Same.", {}),
    ("sam", "Thanks all. Great teamwork this week.", {"react": [(TADA, ["alex", "jordan", "river", "casey"])]}),
    ("alex", "Have a good evening everyone.", {}),
]

HELP = [
    ("river", "How do I add my home server to My Connections?", {}),
    ("sam", "Dashboard, My Connections, Add. Pick the type, enter host and port, save. SSH hosts ask you to confirm the host key on first use.", {"reply": 0}),
    ("river", "The host key prompt scared me a little. Is that normal?", {}),
    ("sam", "Yes. Compare the fingerprint with the one your server shows, then accept. After that the portal warns you if it ever changes.", {"reply": 2}),
    ("river", "Makes sense, thanks!", {"react": [(THUMBS, ["sam"])]}),
    ("jordan", "Can I see which devices are signed in to my account?", {}),
    ("sam", "Account menu, Sessions. You can sign out any single device or all others.", {"reply": 5}),
    ("jordan", "Found it, signed out my old tablet.", {"react": [(CHECK, ["sam"])]}),
    ("casey", "Is there a way to search old messages? I remember a link from last month.", {}),
    ("sam", "Use the search box in chat. Try from:alex has:link to narrow it down.", {"reply": 8}),
    ("casey", "That found it instantly. Thank you!", {}),
    ("alex", "Operators work together too: in:general after:2026-11-01 plus a word.", {}),
]

PROJECTS = [
    ("alex", "Lamp project status: housing printed, waiting on the dimmer module.", {}),
    ("casey", "Slideshow draft is in the shared folder. Feedback welcome.", {}),
    ("jordan", "I added the how-to-join slide. Feels clear to me.", {"reply": 1}),
    ("sam", "Looks good. Maybe add the support channel name at the end.", {"reply": 2}),
    ("jordan", "Done.", {}),
    ("river", "Garden bed plan: raised beds, four by eight feet, cedar boards.", {}),
    ("alex", "Cedar is pricey. Pine with a liner works for a few seasons.", {"reply": 5}),
    ("river", "Good tip, I will price both.", {}),
    ("casey", "Cat photo for morale: https://example.org/photos/cat-on-keyboard", {"react": [(HEART, ["alex", "river", "jordan"])]}),
    ("sam", "Meeting notes are up. Please add your action items before Friday.", {}),
]

DM_LINES = [
    ("alex", "Hey river, are you still bringing basil to the meetup?"),
    ("river", "Yes, two pots. I will keep one for you."),
    ("alex", "Wonderful. I will bring the tomato seedlings in a crate."),
    ("river", "Perfect. Can you also carry the folding table?"),
    ("alex", "Sure, I will fit it in the car."),
    ("river", "Thanks, see you Saturday."),
]


async def seed_people(stage: Stage, admin: Client) -> dict:
    """Create the members through the admin API and give each an avatar. Returns name -> Client."""
    clients: dict = {ADMIN_NAME: admin}
    for name, role, colour, initials in PEOPLE:
        made = await admin.api("POST", "/api/users", {"username": name, "password": PASSWORD})
        if role != "user":
            await admin.api("PUT", f"/api/users/{made['id']}/role", {"role": role})
        c = Client(stage, name)
        await c.login(PASSWORD)
        c.user_id = made["id"]
        await c.api("PUT", "/api/me/avatar", {"color": colour, "initials": initials, "emoji": ""})
        clients[name] = c
    await admin.api("PUT", "/api/me/avatar", {"color": "#6366f1", "initials": "AD", "emoji": ""})
    return clients


async def seed_chat(stage: Stage, clients: dict) -> dict:
    """Three channels with believable talk, sent over the chat WebSocket as the members."""
    admin = clients[ADMIN_NAME]
    chans = {c["name"]: c["id"] for c in (await admin.api("GET", "/api/chat/channels"))["channels"]}
    if "projects" not in chans:
        made = await admin.api("POST", "/api/chat/channels", {"name": "projects", "description": "What everyone is building"})
        chans["projects"] = made.get("id") or made.get("channel", {}).get("id")
    wanted = {"general": GENERAL, "help": HELP, "projects": PROJECTS}
    if "random" in chans:
        await admin.api("DELETE", f"/api/chat/channels/{chans['random']}")
    for extra in [n for n in chans if n not in wanted]:
        chans.pop(extra)
    sockets: dict = {}
    for name in [p[0] for p in PEOPLE] + [ADMIN_NAME]:
        ch = Chat(clients[name])
        await ch.open()
        sockets[name] = ch
    ids: dict = {}
    for chan_name, lines in wanted.items():
        cid = chans[chan_name]
        for ch in sockets.values():
            await ch.send(type="join", channel_id=cid)
        await asyncio.sleep(1.0)
        sent: list = []
        for author, text, extra in lines:
            if author == "POLL":
                owner = sockets[extra["author"]]
                mark = len(owner.frames)
                await owner.send(type="create_poll", question=text, options=extra["options"])
                f = await owner.wait_for("poll_created", mark)
                poll_id = f["poll"]["id"]
                for voter, idx in extra["votes"].items():
                    vs = sockets[voter]
                    await vs.send(type="vote_poll", poll_id=poll_id, option_index=idx)
                    await asyncio.sleep(0.3)
                sent.append(f["message_id"])
                ids["poll"] = (cid, f["message_id"])
                continue
            who = sockets[author]
            if extra.get("anon"):
                await clients[author].api("PUT", "/api/me/anonymous", {"anonymous": True})
                await asyncio.sleep(0.4)
            mid = await who.say(text, reply_to=sent[extra["reply"]] if "reply" in extra else None)
            if extra.get("anon"):
                await clients[author].api("PUT", "/api/me/anonymous", {"anonymous": False})
                await asyncio.sleep(0.4)
            sent.append(mid)
            for emoji, reactors in extra.get("react", []):
                for r in reactors:
                    await sockets[r].send(type="react", message_id=mid, emoji=emoji)
                    await asyncio.sleep(0.25)
            if extra.get("pin"):
                await sockets["sam"].send(type="pin_message", message_id=mid)
                await asyncio.sleep(0.3)
        ids[chan_name] = {"id": cid, "messages": sent}
    # direct messages between alex and river
    a, r = sockets["alex"], sockets["river"]
    await a.send(type="dm_open", user_id=clients["river"].user_id)
    await asyncio.sleep(1.0)
    convs = await clients["alex"].api("GET", "/api/dm/conversations")
    conv = (convs.get("conversations") or convs)[0]
    conv_id = conv["id"]
    for author, text in DM_LINES:
        s = sockets[author]
        await s.send(type="dm_message", conversation_id=conv_id, message=text)
        await asyncio.sleep(0.6)
    ids["dm"] = conv_id
    for s in sockets.values():
        await s.close()
    return ids


class Anon:
    """A fresh unauthenticated HTTP session that appears to come from a documentation address."""

    def __init__(self, stage: Stage, ip: str, agent: str = "Mozilla/5.0 (X11; Linux x86_64) Demo"):
        self.stage = stage
        self.http = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False), cookie_jar=aiohttp.CookieJar(unsafe=True),
            headers={"CF-Connecting-IP": ip, "User-Agent": agent},
            timeout=aiohttp.ClientTimeout(total=30))

    async def login(self, name, password):
        r = await self.http.post(f"{self.stage.direct}/login", json={"username": name, "password": password})
        await r.read()
        return r.status

    async def close(self):
        await self.http.close()


async def seed_operations(stage: Stage, clients: dict) -> dict:
    """Streams, connections, a managed service, webhooks, security events, blocks, a backup, automod."""
    admin, alex = clients[ADMIN_NAME], clients["alex"]
    out: dict = {}

    # two streams (neither live): one public, one private
    pub = await alex.api("POST", "/api/streams", {
        "name": "Friday game night", "description": "Casual co-op games with the group", "is_public": True})
    priv = await alex.api("POST", "/api/streams", {
        "name": "Workshop camera", "description": "Members only, the 3D printer bench", "is_public": False})
    pub_id = (pub.get("stream") or pub)["id"]
    priv_id = (priv.get("stream") or priv)["id"]
    await alex.api("PUT", f"/api/streams/{pub_id}", {
        "allow_unauthenticated": True,
        "golive_message": "{streamer} is live: {title}. Come and hang out!",
        "golive_audience": "followers"})
    out["streams"] = {"public": pub_id, "private": priv_id}

    # personal connections of different types. The portal refuses documentation addresses as
    # targets (they count as private), so these use example.org names that do not resolve; a name
    # that does not resolve may be saved, and nothing here ever connects.
    conns = [
        ("Build server", "ssh", "build.example.org", None, {"username": "builder"}),
        ("Workshop desktop", "vnc", "workshop.example.org", None, {}),
        ("Office PC", "rdp", "office.example.org", None, {}),
        ("Inventory database", "postgresql", "db.example.org", None, {"username": "reader", "database": "inventory"}),
        ("Metrics dashboard", "grafana", "metrics.example.org", 3000, {}),
        ("Media library", "jellyfin", "media.example.org", 8096, {}),
    ]
    for name, typ, host, port, cfg in conns:
        body = {"name": name, "type": typ, "host": host, "config": cfg}
        if port:
            body["port"] = port
        await alex.api("POST", "/api/connections", body)
    # every member has a default "Web Browser" connection; give it a portal page as home page
    # (a same-origin path is loaded directly, so the embedded browser never dials out)
    listing = await alex.api("GET", "/api/connections")
    by_name = {c["name"]: c["id"] for c in (listing.get("connections") if isinstance(listing, dict) else listing)}
    await alex.api("PUT", f"/api/connections/{by_name['Web Browser']}", {"config": {"browser_mode": True, "home_url": "/guides"}})
    out["ssh_connection"] = by_name["Build server"]
    out["browser_connection"] = by_name["Web Browser"]

    # one managed service row, not running
    await admin.api("POST", "/api/managed-services", {
        "name": "demo-relay", "type": "mediamtx", "display_name": "Demo Relay",
        "description": "Streaming relay (demo)", "config": {}, "enabled": False})

    # system webhooks, one per format. The address has to resolve when it is saved (hooks.example.org
    # does not), so these use www.example.org paths. Each is subscribed only to the test event and a
    # staged instance sends nothing at all, so nothing is ever delivered.
    hooks = [
        ("Ops channel (generic)", "generic", "https://www.example.org/hooks/portal-ops", None, False),
        ("Phone alerts (ntfy)", "ntfy", "https://www.example.org/hooks/ntfy/portal-alerts", {}, False),
        ("Pager (gotify)", "gotify", "https://www.example.org/hooks/gotify/message", {"token": "demo-token-not-real"}, False),
        ("Team chat (discord)", "discord", "https://www.example.org/hooks/discord/api/webhooks/0/demo", None, True),
        ("Team chat (slack)", "slack", "https://www.example.org/hooks/slack/services/DEMO/DEMO/demo", None, False),
    ]
    for name, fmt, url, cfg, details in hooks:
        body = {"name": name, "format": fmt, "url": url, "events": ["webhook.test"], "include_details": details}
        if cfg:
            body["format_config"] = cfg
        await admin.api("POST", "/api/admin/webhooks", body)

    # more sign-ins, from other devices and documentation addresses
    for ip, agent in (("192.0.2.44", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile Safari"),
                      ("198.51.100.52", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/126.0")):
        a = Anon(stage, ip, agent)
        await a.login(ADMIN_NAME, stage.admin_password)
        await a.close()

    # failed sign-ins from documentation addresses make security events
    for ip, tries in (("198.51.100.77", 6), ("198.51.100.9", 3), ("198.51.100.130", 2)):
        a = Anon(stage, ip, "python-requests/2.31")
        for i in range(tries):
            await a.login(["root", "administrator", "test", "admin", "guest", "user"][i % 6], "wrong-" + str(i))
        await a.close()
    a = Anon(stage, "192.0.2.61")
    await a.login("river", "not-the-password")
    await a.close()

    # address blocks and the never-ban list
    await admin.api("POST", "/api/admin/blocked-ips", {"ip_address": "198.51.100.77", "reason": "Repeated failed sign-ins"})
    await admin.api("POST", "/api/admin/blocked-ips", {"ip_address": "198.51.100.9", "reason": "Scanner traffic", "duration_hours": 24})
    await admin.api("PUT", "/api/admin/never-ban", {"entries": ["192.0.2.0/24", "198.51.100.200"]})

    # one backup made through the real route
    await admin.api("POST", "/api/admin/backups/run", {})

    # automod rules last so they do not eat the demo messages
    rules = [
        ("Blocked words", "word_filter", "delete", None, {"words": ["spamword", "badword"], "match_mode": "contains"}),
        ("Shouting", "caps_filter", "warn", None, {"min_length": 12, "max_caps_percent": 70}),
        ("Unknown links", "link_filter", "timeout", 300, {"block_all": True, "allow_list": ["example.org"]}),
        ("Mention spam", "mention_spam", "mute", 600, {"max_mentions": 5}),
    ]
    for name, typ, action, dur, cfg in rules:
        body = {"name": name, "type": typ, "action": action, "config": cfg}
        if dur:
            body["action_duration"] = dur
        await admin.api("POST", "/api/admin/automod", body)
    return out


def mark_index_complete(stage: Stage) -> None:
    """A staged instance never starts the one-time search index backfill (it is part of the host
    side effects that stage mode switches off), and until it has run the chat page tells people that
    older results may be missing. Every demo message was indexed with its flags when it was written,
    so the backfill has nothing to do: record it as done, in the stage's own database."""
    import sqlite3
    conn = sqlite3.connect(str(stage.dir / "portal.db"), timeout=30)
    try:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('search_backfill_done', '1')")
        conn.commit()
    finally:
        conn.close()


def spread_timestamps(stage: Stage) -> None:
    """Give the seeded messages believable times: the last two days, with quiet nights.

    The messages were all sent within a few minutes. Only the stage's own database is touched
    (it is a temp file this script made); the index rows get the same times so that the date
    operators of the search match what the chat shows.
    """
    import random
    import sqlite3
    from datetime import datetime, timedelta, timezone

    rng = random.Random(7)
    now = datetime.now(timezone.utc)
    conn = sqlite3.connect(str(stage.dir / "portal.db"), timeout=30)
    try:
        groups = {}
        for mid, cid in conn.execute("SELECT id, channel_id FROM chat_messages ORDER BY id"):
            groups.setdefault(("chat", cid), []).append(mid)
        for mid, cid in conn.execute("SELECT id, conversation_id FROM dm_messages ORDER BY id"):
            groups.setdefault(("dm", cid), []).append(mid)
        for (kind, _), ids in groups.items():
            # walk backwards from shortly before now; a long gap every so often
            t = now - timedelta(minutes=rng.randint(4, 25))
            times = []
            for i in range(len(ids)):
                times.append(t)
                gap = rng.randint(1, 9) if rng.random() > 0.08 else rng.randint(240, 540)
                t -= timedelta(minutes=gap, seconds=rng.randint(0, 50))
            times.reverse()
            for mid, when in zip(ids, times):
                stamp = when.isoformat()
                if kind == "chat":
                    conn.execute("UPDATE chat_messages SET created_at = ? WHERE id = ?", (stamp, mid))
                    conn.execute("UPDATE chat_fts_map SET created_at = ? WHERE message_id = ?", (stamp, mid))
                else:
                    conn.execute("UPDATE dm_messages SET created_at = ? WHERE id = ?", (stamp, mid))
                    try:
                        conn.execute("UPDATE dm_fts_map SET created_at = ? WHERE message_id = ?", (stamp, mid))
                    except sqlite3.Error:
                        pass
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Taking the pictures
# ---------------------------------------------------------------------------

SHOTS: dict = {}     # name -> function(s), in the order they are defined


def shot(name: str):
    def deco(fn):
        SHOTS[name] = fn
        return fn
    return deco


# A made-up link preview answer for the chat page, so the portal never fetches a real address
# while a picture is taken (the preview route would otherwise make the staged server dial out).
NO_PREVIEW = json.dumps({})


class Shooter:
    def __init__(self, playwright, stage: Stage, out: Path, chromium: str, info: dict, optimize: bool):
        self.stage, self.out, self.info, self.optimize = stage, out, info, optimize
        self.browser = playwright.chromium.launch(
            executable_path=chromium, headless=True,
            args=["--no-sandbox", f"--host-resolver-rules=MAP {DEMO_HOST} 127.0.0.1",
                  "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required"])
        self.contexts: list = []
        self.written: list = []
        self.presence_pages: list = []
        self._admin_ctx = None

    @property
    def admin_ctx(self):
        if self._admin_ctx is None:
            ctx = self.context(ADMIN_NAME)
            ctx.route("**/api/system/health", lambda r: r.fulfill(
                status=200, content_type="application/json", body=json.dumps(DEMO_HEALTH)))
            ctx.add_init_script(DEMO_BACKUPS_PATCH)
            self._admin_ctx = ctx
        return self._admin_ctx

    # -- contexts and pages -------------------------------------------------
    def context(self, user: str | None, viewport=None, theme: str | None = None, mobile: bool = False, scale: int = 1,
                address: str | None = None):
        opts = dict(viewport=viewport or VIEWPORT, ignore_https_errors=True, device_scale_factor=scale,
                    extra_http_headers={"CF-Connecting-IP": address or ADDRESSES.get(user or "", "192.0.2.10")},
                    user_agent=DESKTOP_AGENT, locale="en-US", timezone_id="UTC")
        if mobile:
            opts.update(device_scale_factor=2, is_mobile=True, has_touch=True)
        ctx = self.browser.new_context(**opts)
        init = "localStorage.setItem('portal_welcome_dismissed','1');"
        if theme:
            init += f"localStorage.setItem('portal-theme','{theme}');"
        ctx.add_init_script(init)
        ctx.route("**/api/chat/link-preview*", lambda r: r.fulfill(status=200, content_type="application/json", body=NO_PREVIEW))
        self.contexts.append(ctx)
        if user:
            page = ctx.new_page()
            page.goto(f"{self.stage.base}/login")
            password = self.stage.admin_password if user == ADMIN_NAME else PASSWORD
            status = page.evaluate(
                "async (b) => (await fetch('/login', {method: 'POST', headers: {'Content-Type': 'application/json'},"
                " body: JSON.stringify(b)})).status", {"username": user, "password": password})
            if status != 200:
                raise Fail(f"browser login of {user} failed: {status}")
            page.close()
        return ctx

    def open(self, ctx, path: str, ready: str | None = None, settle: int = 700):
        page = ctx.new_page()
        problems = []
        page.on("response", lambda r: problems.append(f"{r.status} {r.url}") if r.status >= 400 else None)
        page.goto(self.stage.base + path)
        page.wait_for_load_state("networkidle")
        if ready:
            page.wait_for_selector(ready, timeout=15000)
        page.wait_for_timeout(settle)
        page.problems = problems
        return page

    # -- output -------------------------------------------------------------
    def save(self, name: str, source) -> None:
        """source: a playwright Page (the viewport) or Locator (one element)."""
        from io import BytesIO
        from PIL import Image
        self.write(name, Image.open(BytesIO(source.screenshot())).convert("RGB"))

    def write_bytes(self, name: str, raw: bytes) -> None:
        from io import BytesIO
        from PIL import Image
        self.write(name, Image.open(BytesIO(raw)).convert("RGB"))

    def write(self, name: str, img) -> None:
        self.out.mkdir(parents=True, exist_ok=True)
        path = self.out / f"{name}.png"
        img.save(path, "PNG", optimize=self.optimize)
        self.written.append(path)
        print(f"wrote {path.name}  {img.size[0]}x{img.size[1]}  {path.stat().st_size // 1024} KB", flush=True)

    def start_presence(self) -> None:
        """Keep the other members' chat pages open so that the online list and the counters are not empty."""
        for name in ("sam", "river", "jordan", "casey"):
            ctx = self.context(name)
            page = ctx.new_page()
            page.goto(self.stage.base + "/chat")
            page.wait_for_load_state("networkidle")
            self.presence_pages.append(page)
        self.contexts[-1].pages[0].wait_for_timeout(1500)

    def close(self) -> None:
        for c in self.contexts:
            try:
                c.close()
            except Exception:
                pass
        self.browser.close()


def stack(images: list, gap: int = 16):
    """Several element pictures one above the other on the page's dark background colour."""
    from PIL import Image
    width = max(i.size[0] for i in images)
    height = sum(i.size[1] for i in images) + gap * (len(images) - 1)
    canvas = Image.new("RGB", (width, height), images[0].getpixel((2, 2)))
    y = 0
    for i in images:
        canvas.paste(i, (0, y))
        y += i.size[1] + gap
    return canvas


def stack_centered(images: list, gap: int = 16):
    """Element pictures one above the other, each centred, on the first picture's background colour."""
    from PIL import Image
    width = max(i.size[0] for i in images)
    height = sum(i.size[1] for i in images) + gap * (len(images) - 1)
    canvas = Image.new("RGB", (width, height), images[0].getpixel((2, 2)))
    y = 0
    for i in images:
        canvas.paste(i, ((width - i.size[0]) // 2, y))
        y += i.size[1] + gap
    return canvas


def element_image(locator):
    from io import BytesIO
    from PIL import Image
    return Image.open(BytesIO(locator.screenshot())).convert("RGB")


# -- plain pages -----------------------------------------------------------

@shot("login")
def _login(s):
    ctx = s.context(None)
    page = s.open(ctx, "/login", "input[type=password]")
    s.save("login", page)


@shot("dashboard")
def _dashboard(s):
    page = s.open(s.context(ADMIN_NAME), "/", ".service-card, .stat-card")
    s.save("dashboard", page)


@shot("themes")
def _themes(s):
    page = s.open(s.context(ADMIN_NAME), "/", ".stat-card")
    page.click(".navbar-theme-btn")
    page.wait_for_selector(".theme-picker-dropdown.open")
    page.wait_for_timeout(400)
    s.save("themes", page)


@shot("dashboard-light")
def _light(s):
    page = s.open(s.context(ADMIN_NAME, theme="light"), "/", ".stat-card")
    s.save("dashboard-light", page)


@shot("dashboard-hc")
def _hc(s):
    page = s.open(s.context(ADMIN_NAME, theme="high-contrast"), "/", ".stat-card")
    s.save("dashboard-hc", page)


@shot("about")
def _about(s):
    s.save("about", s.open(s.context(ADMIN_NAME), "/about"))


@shot("api-docs")
def _apidocs(s):
    s.save("api-docs", s.open(s.context(ADMIN_NAME), "/api-docs"))


@shot("guides")
def _guides(s):
    s.save("guides", s.open(s.context(ADMIN_NAME), "/guides"))


@shot("guides-detail")
def _guides_detail(s):
    page = s.open(s.context(ADMIN_NAME), "/guides")
    page.get_by_text("Plex", exact=True).first.click()      # a guide in the sidebar scrolls to it
    page.wait_for_timeout(1500)
    s.save("guides-detail", page)


@shot("streams")
def _streams(s):
    # as alex: other members' public streams with the Follow toggle, two of them live
    page = s.open(s.context("alex"), "/streams", ".stream-follow-btn", settle=1500)
    s.save("streams", page)


@shot("chat-golive")
def _chat_golive(s):
    # the go-live cards in the announce channel (general) and the live-now strip above the chat
    page = chat_page(s)
    page.wait_for_selector(".stream-card-msg", timeout=15000)
    page.wait_for_selector("#live-now-strip a", timeout=15000)
    page.evaluate("""() => { const box = document.getElementById('chat-messages');
        box.scrollTop = box.scrollHeight; window.scrollTo(0, 0); }""")
    page.wait_for_timeout(800)
    s.save("chat-golive", page)


@shot("watch-chat")
def _watch_chat(s):
    # the watch page of river's live stream as alex: the chat with a pinned banner and a Mod badge,
    # and a viewer count. No video plays here, so the viewers' own heartbeats are sent by the
    # members' open chat pages (the same call the watch page makes while the video plays); the
    # count is written about every 5 seconds, so wait for it before the page is opened.
    watch = s.info["watch"]
    beat = ("() => { const b = () => fetch('/api/stream/" + watch["public_key"] + "/viewer',"
            " {method: 'POST', credentials: 'include'}); b(); setInterval(b, 5000); }")
    for p in s.presence_pages:
        p.evaluate(beat)
    s.presence_pages[0].wait_for_timeout(8000)
    page = s.open(s.context("alex"), f"/watch/{watch['stream_id']}", ".watch-pinned.show", settle=2500)
    page.wait_for_selector(".mod-badge", timeout=15000)
    page.evaluate("""() => { const box = document.getElementById('chat-messages'); box.scrollTop = box.scrollHeight; }""")
    page.wait_for_timeout(800)
    s.save("watch-chat", page)


@shot("streams-settings")
def _stream_settings(s):
    # the stream's settings window belongs to the dashboard's My Streams tab; a tall window shows all of it
    ctx = s.context("alex", viewport={"width": 1280, "height": 2400})
    page = s.open(ctx, "/", ".stat-card")
    page.evaluate("switchTab('my-streams')")
    page.wait_for_selector("#tab-my-streams .stream-card, .stream-card", timeout=15000)
    page.wait_for_timeout(1000)
    page.locator(".stream-card", has_text="Friday game night").get_by_role("button", name="Manage").first.click()
    page.wait_for_selector("#stream-details-modal .info-section", state="visible")
    page.evaluate("""() => document.querySelectorAll('#stream-details-modal .modal-content, #stream-details-modal .modal-body')
        .forEach(el => { el.style.maxHeight = 'none'; el.style.overflow = 'visible'; })""")
    page.wait_for_timeout(1000)
    s.save("streams-settings", page.locator("#stream-details-modal .modal-content"))


# Made-up host numbers for the admin pages: the real health call would report the
# machine this script runs on. Same shape as GET /api/system/health.
_GB = 1024 ** 3
DEMO_HEALTH = {
    "cpu": {"percent": 12.5, "count": 4, "load_avg": [0.42, 0.37, 0.31]},
    "memory": {"total": 8 * _GB, "used": int(2.6 * _GB), "available": int(5.4 * _GB), "percent": 32.5},
    "disk": {"total": 64 * _GB, "used": 21 * _GB, "free": 43 * _GB, "percent": 32.8},
    "process": {"rss": 180 * 1024 ** 2, "vms": 900 * 1024 ** 2, "threads": 14, "pid": 1},
    "uptime_seconds": 12 * 86400 + 5 * 3600,
    "net_io": {"bytes_sent": 0, "bytes_recv": 0},
    "disk_io": {"read_bytes": 0, "write_bytes": 0},
    "swap": {"total": 0, "used": 0, "percent": 0},
    "open_files": 24,
    "connections_count": 9,
}


# Patches the free-space figure in the backups answer inside the page (the answer itself comes
# from the staged instance; only the figure would describe the machine the script runs on).
DEMO_BACKUPS_PATCH = """
(() => {
  const orig = window.fetch;
  window.fetch = async function (...args) {
    const res = await orig.apply(this, args);
    const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
    if (!/\\/api\\/admin\\/backups(\\?|$)/.test(url)) return res;
    const data = await res.clone().json();
    if (data && data.free_bytes != null) data.free_bytes = 48 * 1024 * 1024 * 1024;
    return new Response(JSON.stringify(data), {status: res.status, headers: {'Content-Type': 'application/json'}});
  };
})();
"""


# A canned, fictional directory listing for the file manager (no server is ever dialled).
_NOW = int(time.time())
DEMO_LISTING = [
    {"name": "projects", "type": "directory", "size": 4096, "permissions": "rwxr-xr-x", "modified": _NOW - 86400 * 2},
    {"name": "backups", "type": "directory", "size": 4096, "permissions": "rwxr-x---", "modified": _NOW - 3600 * 7},
    {"name": "photos", "type": "directory", "size": 4096, "permissions": "rwxr-xr-x", "modified": _NOW - 86400 * 11},
    {"name": "notes.txt", "type": "file", "size": 2210, "permissions": "rw-r--r--", "modified": _NOW - 3600 * 30},
    {"name": "meetup-slides.pdf", "type": "file", "size": 4812093, "permissions": "rw-r--r--", "modified": _NOW - 86400 * 3},
    {"name": "recipe-bean-chili.md", "type": "file", "size": 1432, "permissions": "rw-r--r--", "modified": _NOW - 86400 * 5},
    {"name": "lamp-housing.stl", "type": "file", "size": 912344, "permissions": "rw-r--r--", "modified": _NOW - 3600 * 9},
]


@shot("files")
def _files(s):
    ctx = s.context("alex")
    ctx.route("**/api/sftp/*/list*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                         body=json.dumps(DEMO_LISTING)))
    page = s.open(ctx, "/files")
    page.wait_for_selector("#sftp-conn-select option:nth-child(2)", state="attached")
    page.select_option("#sftp-conn-select", index=1)
    page.wait_for_selector("#sftp-file-body-single tr td", timeout=10000)
    page.wait_for_timeout(800)
    s.save("files", page)


@shot("hostkey-prompt")
def _hostkey(s):
    page = s.open(s.context("alex"), "/files")
    page.evaluate("""() => HostKey.prompt({
        state: 'unpinned', host: 'build.example.org', port: 22, can_accept: true,
        fingerprint: 'SHA256:3F9c1b0aWq7mNe2xYtKd5vLr8uPzHs4jGoXiCa6BfE0',
        accept_url: '/api/connections/demo/host-key/accept', accept_token: 'demo',
        message: 'This server has not been seen before. Compare the fingerprint with the one the server shows, then accept it.'
    }, {})""")
    page.wait_for_timeout(800)
    box = page.get_by_text("Confirm host key").locator("xpath=..").bounding_box()
    pad = 40
    clip = {"x": box["x"] - pad, "y": box["y"] - pad, "width": box["width"] + 2 * pad, "height": box["height"] + 2 * pad}
    s.write_bytes("hostkey-prompt", page.screenshot(clip=clip))


@shot("browser")
def _browser(s):
    page = s.open(s.context("alex"), f"/browser?connection={s.info['browser_connection']}")
    s.save("browser", page)


@shot("terminal-keybar")
def _terminal(s):
    ctx = s.context("alex", viewport=PHONE, mobile=True)
    page = ctx.new_page()
    page.route_web_socket("**/ws/**", lambda ws: None)     # accepted and left silent: nothing is dialled
    page.goto(f"{s.stage.base}/terminal/connect?connection={s.info['ssh_connection']}")
    page.wait_for_load_state("networkidle")
    page.wait_for_selector(".keybar", state="attached")
    if not page.evaluate("document.body.classList.contains('keybar-on')"):
        page.click("#keybar-toggle")        # the bar is off by default until a touch is seen
    page.wait_for_selector(".keybar", state="visible")
    page.wait_for_timeout(1500)
    s.save("terminal-keybar", page)


# -- chat ------------------------------------------------------------------

def chat_page(s, user: str = "alex", channel: str = "general"):
    page = s.open(s.context(user), "/chat", ".message[data-message-id]", settle=1200)
    return page


def check_index_complete(s) -> None:
    """The portal would show a note about search results that may miss older messages until its
    one-time index backfill is done (see mark_index_complete); make sure the note will not appear."""
    page = s.context("sam").new_page()
    page.goto(s.stage.base + "/login")
    done = page.evaluate("async () => { const r = await fetch('/api/chat/search?q=lamp'); "
                         "const j = await r.json(); return !!j.index_complete; }")
    page.close()
    if not done:
        raise Fail("the search index is not reported complete")


@shot("chat")
def _chat(s):
    page = chat_page(s)
    # scroll so that the poll is at the top of the message list
    poll_id = s.info["poll"][1]
    page.evaluate(f"""() => {{ const m = document.querySelector('.message[data-message-id="{poll_id}"]');
        m.scrollIntoView({{block: 'start'}}); }}""")
    page.wait_for_timeout(600)
    s.save("chat", page)


@shot("dms")
def _dms(s):
    page = chat_page(s)
    page.evaluate(f"openDmConversation({s.info['dm']})")
    page.wait_for_function("() => document.getElementById('chat-messages').textContent.includes('basil')", timeout=10000)
    page.wait_for_timeout(900)
    s.save("dms", page)


@shot("chat-search")
def _chat_search(s):
    page = chat_page(s)
    check_index_complete(s)
    page.evaluate("toggleSearchBar()")
    page.fill("#search-input", "from:casey has:link")
    page.keyboard.press("Enter")
    page.wait_for_selector(".search-result", timeout=10000)
    page.wait_for_timeout(800)
    s.save("chat-search", page)


@shot("chat-scrollback")
def _chat_scrollback(s):
    page = chat_page(s)
    check_index_complete(s)
    page.evaluate("toggleSearchBar()")
    page.fill("#search-input", "tomato seedlings in:general")
    page.keyboard.press("Enter")
    page.wait_for_selector(".search-result", timeout=10000)
    page.locator(".search-result").first.click()
    page.wait_for_selector("#history-jump-btn", state="visible", timeout=10000)
    page.wait_for_timeout(1500)
    page.evaluate("window.scrollTo(0, 0)")
    page.evaluate("document.getElementById('search-input').value = ''")
    page.locator("#search-input").evaluate("el => { const bar = el.closest('.search-bar, #search-bar') || el.parentElement; bar.style.display = 'none'; }")
    page.wait_for_timeout(500)
    s.save("chat-scrollback", page)


@shot("voice-settings")
def _voice_settings(s):
    page = chat_page(s)
    page.evaluate("openVoiceSettings()")
    page.wait_for_selector("#voice-settings-modal.active")
    # the fake microphone beeps; wait for the meter to show a level
    for _ in range(40):
        width = page.evaluate("parseFloat(document.getElementById('voice-meter-fill').style.width || '0')")
        if width and width > 25:
            break
        page.wait_for_timeout(250)
    s.save("voice-settings", page.locator("#voice-settings-modal .voice-settings-content"))


# -- account ---------------------------------------------------------------

@shot("sessions")
def _sessions(s):
    ctx = s.context(ADMIN_NAME, viewport={"width": 1280, "height": 1100})
    page = s.open(ctx, "/", ".stat-card")
    page.evaluate("showProfileModal()")
    page.wait_for_selector("#sessions-list", state="visible", timeout=10000)
    page.wait_for_timeout(800)
    # a few rows are enough; a wider window keeps the last column whole
    page.evaluate("""() => {
        document.querySelectorAll('#sessions-list tbody tr').forEach((tr, i) => { if (i >= 5) tr.style.display = 'none'; });
        const box = document.getElementById('sessions-section').closest('.modal-content');
        if (box) { box.style.maxWidth = '760px'; box.style.width = '760px'; }
        document.getElementById('sessions-list').style.overflow = 'visible';
    }""")
    page.get_by_role("heading", name="Sessions").evaluate("el => el.scrollIntoView({block: 'start'})")
    page.wait_for_timeout(500)
    head = page.get_by_role("heading", name="Sessions").bounding_box()
    body = page.locator("#sessions-section").bounding_box()
    pad = 24
    x = body["x"] - pad
    y = head["y"] - pad
    clip = {"x": x, "y": y, "width": body["width"] + 2 * pad,
            "height": body["y"] + body["height"] - head["y"] + 2 * pad}
    s.write_bytes("sessions", page.screenshot(clip=clip))


# -- admin -----------------------------------------------------------------

def admin_page(s, tab: str | None = None, ready: str | None = None):
    page = s.open(s.admin_ctx, "/admin", ".tab-btn")
    if tab:
        page.evaluate(f"showTab('{tab}')")
        if ready:
            page.wait_for_selector(ready, timeout=15000)
        page.wait_for_timeout(1000)
    return page


@shot("admin")
def _admin(s):
    page = admin_page(s, "overview", "#tab-overview .admin-card")
    s.save("admin", page)


@shot("sysmon")
def _sysmon(s):
    page = admin_page(s, "overview", "#tab-overview .admin-card")
    card = page.locator("#tab-overview .admin-card", has_text="System Resources").first
    box = card.bounding_box()
    # the three gauges only: not the load, process and uptime rows below them
    s.write_bytes("sysmon", page.screenshot(clip={"x": box["x"], "y": box["y"], "width": box["width"], "height": 196}))


@shot("sysmon-services")
def _sysmon_services(s):
    page = admin_page(s, "services", "#tab-services .service-card, #tab-services .admin-card")
    s.save("sysmon-services", page)


@shot("admin-backups")
def _backups(s):
    page = admin_page(s, "settings", "#backups-body table")
    s.save("admin-backups", page.locator("#backups-card"))


@shot("admin-security-events")
def _secevents(s):
    page = admin_page(s, "audit", "#audit-chip-security")
    page.click("#audit-chip-security")
    page.wait_for_selector("#tab-audit table tbody tr", timeout=10000)
    page.wait_for_timeout(1000)
    s.save("admin-security-events", page)


@shot("admin-blocking")
def _blocking(s):
    page = admin_page(s, "system", "#tab-system")
    page.evaluate("showSysSubTab('network')")
    page.wait_for_selector("#blocked-ips-body tr", timeout=10000)
    page.wait_for_timeout(600)
    # only the blocked-address section: the rest of the Network view lists this host's own connections
    blocked = element_image(page.locator(".sys-net-section", has_text="Blocked IPs").first)
    page.evaluate("showTab('settings')")
    page.wait_for_selector("#neverban-body input, #neverban-body textarea", timeout=10000)
    page.wait_for_timeout(600)
    # the host's own addresses are real ones: leave that row out of the picture
    page.evaluate("""() => document.querySelectorAll('#neverban-card tr').forEach(tr => {
        if (/own addresses/i.test(tr.textContent)) tr.style.display = 'none'; })""")
    never = element_image(page.locator("#neverban-card"))
    s.write("admin-blocking", stack([blocked, never]))


@shot("admin-cloudflare")
def _cloudflare(s):
    page = admin_page(s, "settings", "#cfranges-body .btn, #cfranges-body input")
    s.save("admin-cloudflare", page.locator("#cfranges-card"))


@shot("admin-webhooks")
def _webhooks(s):
    page = admin_page(s, "webhooks", "#tab-webhooks table tbody tr, #tab-webhooks .wh-row")
    s.save("admin-webhooks", page)


@shot("admin-webhook-edit")
def _webhook_edit(s):
    # a tall window so that the whole dialog, down to the two switches, is in view
    ctx = s.context(ADMIN_NAME, viewport={"width": 1280, "height": 1500})
    page = s.open(ctx, "/admin", ".tab-btn")
    page.evaluate("showTab('webhooks')")
    page.wait_for_selector("#tab-webhooks table tbody tr", timeout=15000)
    page.wait_for_timeout(1000)
    page.locator("#tab-webhooks button", has_text="Edit").nth(3).click()      # the Discord hook
    page.wait_for_selector("#wh-modal")
    page.wait_for_timeout(800)
    s.save("admin-webhook-edit", page.locator("#wh-modal > div"))


@shot("admin-automod")
def _automod(s):
    page = admin_page(s, "automod", "#tab-automod table tbody tr, #tab-automod .automod-rule")
    s.save("admin-automod", page)


@shot("share-expiry")
def _share_expiry(s):
    # a tall window so that the whole dialog is in view
    ctx = s.context("alex", viewport={"width": 1280, "height": 1500})
    page = s.open(ctx, "/", ".connection-card, .service-card")
    page.evaluate("(id) => showShareConnectionModal(id, 'Build server')", s.info["ssh_connection"])
    page.wait_for_selector("#share-current-list .share-row, #share-current-list li, #share-current-list div", timeout=15000)
    page.wait_for_timeout(800)
    page.click("button:has-text('All my shares')")
    page.wait_for_selector("#all-shares-list", state="visible")
    page.wait_for_timeout(800)
    # a native list does not draw its pop-up in a headless picture: show it open, as a list box,
    # with the default (30 days) chosen
    page.evaluate("() => { const e = document.getElementById('share-duration'); e.value = '30d'; e.size = e.options.length; }")
    page.wait_for_timeout(300)
    s.save("share-expiry", page.locator("#share-connection-modal .modal-content"))


@shot("api-keys")
def _api_keys(s):
    ctx = s.context(ADMIN_NAME, viewport={"width": 1280, "height": 1700})
    page = s.open(ctx, "/", ".stat-card, .service-card")
    page.evaluate("() => showApiKeysModal()")
    page.wait_for_selector("#api-keys-modal .modal-content", state="visible")
    page.wait_for_timeout(800)
    page.evaluate("() => showCreateApiKeyForm()")
    page.wait_for_selector("#api-key-scope-picker input", timeout=15000)
    page.fill("#api-key-name", "Nightly export")
    page.uncheck(".api-key-scope-cb[value='access:*']")
    page.fill("#api-key-cidrs", "203.0.113.0/24")
    # the window is narrow and clips the right-hand columns of the key list: widen it for the picture
    page.evaluate("() => { const m = document.querySelector('#api-keys-modal .modal-content'); m.style.maxWidth = '1180px'; m.style.width = '1180px'; }")
    page.wait_for_timeout(500)
    s.save("api-keys", page.locator("#api-keys-modal .modal-content"))


@shot("admin-signin-limits")
def _signin_limits(s):
    page = admin_page(s, "settings", "#loginban-body input, #loginban-body .btn")
    page.wait_for_selector("#proxylimit-body input, #proxylimit-body .btn", timeout=15000)
    page.wait_for_timeout(500)
    page.evaluate("() => ['loginban-card', 'proxylimit-card'].forEach(id => { const c = document.getElementById(id); c.style.height = 'auto'; c.style.minHeight = '0'; c.style.alignSelf = 'flex-start'; c.style.flex = '0 0 auto'; })")
    page.wait_for_timeout(300)
    s.write("admin-signin-limits", stack([element_image(page.locator("#loginban-card")),
                                          element_image(page.locator("#proxylimit-card"))]))


@shot("chat-notify-menu")
def _chat_notify_menu(s):
    page = chat_page(s, "alex")
    # sam (a chat page that is already open) writes in a channel alex has not joined: the badge appears live
    sam = s.presence_pages[0]
    sam.evaluate("switchChannel('projects')")
    sam.wait_for_function("() => document.getElementById('chat-messages').textContent.length > 20", timeout=10000)
    sam.wait_for_timeout(1500)
    sam.fill("#chat-input", "Pushed the new parts list, take a look when you have a minute")
    sam.evaluate("sendMessage()")
    row = page.locator(".channel-item[data-channel='projects']")
    row.locator(".unread-badge").wait_for(timeout=10000)
    page.wait_for_timeout(500)
    row.hover()
    row.locator(".ch-notif-bell").click()
    page.wait_for_selector(".notify-menu", timeout=5000)
    page.wait_for_timeout(500)
    s.save("chat-notify-menu", page)


@shot("phone-notifications")
def _phone_notifications(s):
    ctx = s.context("alex", viewport={"width": 1280, "height": 1300})
    ctx.grant_permissions(["notifications"], origin=s.stage.base)
    page = s.open(ctx, "/", ".stat-card")
    page.evaluate("showProfileModal()")
    page.wait_for_selector("#push-settings #push-enable-switch", state="visible", timeout=15000)
    page.wait_for_selector("#push-settings h5", state="visible", timeout=15000)
    page.wait_for_timeout(800)
    page.get_by_role("heading", name="Phone notifications").evaluate("el => el.scrollIntoView({block: 'start'})")
    page.wait_for_timeout(500)
    head = page.get_by_role("heading", name="Phone notifications").bounding_box()
    body = page.locator("#push-settings").bounding_box()
    pad = 24
    clip = {"x": body["x"] - pad, "y": head["y"] - pad, "width": body["width"] + 2 * pad,
            "height": body["y"] + body["height"] - head["y"] + 2 * pad}
    s.write_bytes("phone-notifications", page.screenshot(clip=clip))


@shot("admin-push")
def _admin_push(s):
    page = admin_page(s, "settings", "#push-admin-card")
    page.wait_for_function("() => document.getElementById('push-admin-hosts').value.includes('push.example.org')", timeout=15000)
    page.wait_for_timeout(500)
    page.evaluate("() => { const c = document.getElementById('push-admin-card'); c.style.height = 'auto'; c.style.minHeight = '0'; c.style.alignSelf = 'flex-start'; }")
    page.wait_for_timeout(300)
    s.write("admin-push", element_image(page.locator("#push-admin-card")))


# -- 1.20.0: recordings, prune, retention, voice -----------------------------

def forbidden_strings(s) -> list:
    """What must never appear in a picture: this machine's host name, user name and home directory, the
    staged instance's temporary directory and the source tree. Short values are ignored (a two-letter
    user name would match everywhere)."""
    import getpass
    import socket
    vals = [socket.gethostname(), socket.getfqdn(), getpass.getuser(), str(Path.home()),
            str(s.stage.dir), "portal-shots-", str(REPO)]
    return sorted({v for v in vals if v and len(v) >= 4 and v.lower() not in ("localhost", "root")})


def assert_clean(s, page, name: str, scope: str | None = None) -> None:
    """Fail the picture when its page text (visible or not, and every input value) names something real.
    scope: a selector, for a picture of one element of a page that holds other things of this machine."""
    text = page.evaluate(
        "(scope) => { const r = scope ? document.querySelector(scope) : document.body;"
        " return r.textContent + ' ' + Array.from(r.querySelectorAll('input,textarea,select'))"
        ".map(e => e.value).join(' ') + ' ' + Array.from(r.querySelectorAll('[title],[alt]'))"
        ".map(e => (e.getAttribute('title') || '') + ' ' + (e.getAttribute('alt') || '')).join(' '); }", scope).lower()
    for bad in forbidden_strings(s):
        if bad.lower() in text:
            raise Fail(f"picture {name}: the page text holds a value of this machine ({len(bad)} characters)")


@shot("admin-recordings")
def _admin_recordings(s):
    page = s.open(s.admin_ctx, "/admin", ".tab-btn")
    page.wait_for_selector("#tab-btn-recordings", state="visible", timeout=15000)
    page.click("#tab-btn-recordings")
    page.wait_for_selector("#rec-body button[data-action=play]", timeout=15000)
    page.wait_for_timeout(500)
    # the tab bar and the tab, before the player opens over them
    bar = page.locator("#tab-btn-recordings").locator("xpath=..").bounding_box()
    tab = page.locator("#tab-recordings").bounding_box()
    from io import BytesIO
    from PIL import Image
    listing = Image.open(BytesIO(page.screenshot(clip={
        "x": tab["x"], "y": bar["y"], "width": tab["width"], "height": tab["y"] + tab["height"] - bar["y"]}))).convert("RGB")
    page.evaluate("() => { document.getElementById('rec-speed').value = '4'; }")   # the modal is closed until Play
    row = page.locator("#rec-body tr", has_text="Build server").first
    row.locator("button[data-action=play]").click()
    page.wait_for_function("() => document.getElementById('rec-play-status').textContent === 'Finished'", timeout=40000)
    page.wait_for_timeout(500)
    if "ping statistics" not in page.evaluate("() => document.getElementById('rec-player').textContent"):
        raise Fail("the player did not show the end of the demo recording")
    assert_clean(s, page, "admin-recordings")
    # the player covers the list (the modal dims the page), so the picture is the tab above the player
    player = element_image(page.locator("#rec-modal .modal-content"))
    s.write("admin-recordings", stack_centered([listing, player]))


def _chat_admin_general(s):
    ctx = s.admin_ctx
    page = s.open(ctx, "/chat", ".message[data-message-id]", settle=1200)
    page.wait_for_selector("#prune-btn", state="visible", timeout=15000)
    return page


@shot("chat-prune")
def _chat_prune(s):
    page = _chat_admin_general(s)
    page.click("#prune-btn")
    page.wait_for_selector(".cr-modal input[type=datetime-local]", timeout=10000)
    # a range that covers the demo conversation: the last three days
    page.evaluate("""() => {
        const pad = (n) => String(n).padStart(2, '0');
        const f = (d) => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        const ins = document.querySelectorAll('.cr-modal input[type=datetime-local]');
        const now = new Date();
        ins[0].value = f(new Date(now.getTime() - 3 * 86400000));
        ins[1].value = f(now);
        ins[0].dispatchEvent(new Event('input', {bubbles: true}));
        ins[1].dispatchEvent(new Event('input', {bubbles: true}));
    }""")
    # the dry run only: the Remove button is never pressed
    page.locator(".cr-modal button", has_text="Count").click()
    page.wait_for_function("() => /message/.test(document.querySelector('.cr-modal .cr-result').textContent)", timeout=15000)
    page.wait_for_timeout(400)
    assert_clean(s, page, "chat-prune")
    s.save("chat-prune", page.locator(".cr-modal .modal-content"))


@shot("chat-retention")
def _chat_retention(s):
    page = _chat_admin_general(s)
    page.click("#retention-btn")
    page.wait_for_selector(".cr-modal .cr-field input", timeout=10000)
    fields = page.locator(".cr-modal .cr-field input")
    fields.nth(0).fill("90")
    fields.nth(1).fill("30")
    page.wait_for_timeout(300)
    assert_clean(s, page, "chat-retention")
    # typed, never saved: the Save button is not pressed
    s.save("chat-retention", page.locator(".cr-modal .modal-content"))



NO_ICE = json.dumps({"ice_servers": []})


@shot("voice-moderation")
def _voice_moderation(s):
    """Two demo members in one voice room. The browsers use Chromium's fake microphone; the portal's ICE
    server list is answered empty, so no STUN or TURN address is ever dialled and the two browsers
    connect over this machine's own interfaces. The quality bars are the real getStats readings."""
    route = lambda r: r.fulfill(status=200, content_type="application/json", body=NO_ICE)
    admin_ctx = s.context(ADMIN_NAME, scale=2)       # twice the pixels: the bars are small
    admin_ctx.route("**/api/voice/ice-servers", route)
    alex_ctx = s.context("alex")
    alex_ctx.route("**/api/voice/ice-servers", route)
    alex = s.open(alex_ctx, "/chat", ".message[data-message-id]", settle=800)
    mod = s.open(admin_ctx, "/chat", ".message[data-message-id]", settle=800)
    for pg in (alex, mod):
        pg.click("#voice-join-btn")
        pg.wait_for_selector("#voice-controls.active", timeout=20000)
    mod.wait_for_selector("#voice-users-mini .voice-user-mini[data-voice-uid]", timeout=20000)
    # real figures only: wait until the bars of the other member are lit (the first reading takes a few seconds)
    mod.wait_for_function(
        "() => document.querySelectorAll('#voice-users-mini .vq-bar.on').length >= 1", timeout=30000)
    mod.wait_for_timeout(1500)
    tile = mod.locator("#voice-users-mini .voice-user-mini[data-voice-uid]").first
    box = tile.bounding_box()
    # the right-click lands on the lower edge of the tile, so the menu opens below it and the tile stays in view
    tile.click(button="right", position={"x": 6, "y": max(1, box["height"] - 2)})
    mod.wait_for_selector(".voice-user-menu", timeout=10000)
    mod.wait_for_timeout(400)
    assert_clean(s, mod, "voice-moderation")
    bar = mod.locator("#voice-controls").bounding_box()
    menu = mod.locator(".voice-user-menu").bounding_box()
    top = min(bar["y"], menu["y"]) - 12
    bottom = max(bar["y"] + bar["height"], menu["y"] + menu["height"]) + 12
    left = min(bar["x"], menu["x"]) - 12
    right = max(bar["x"] + bar["width"], menu["x"] + menu["width"]) + 12
    s.write_bytes("voice-moderation", mod.screenshot(clip={"x": max(0, left), "y": max(0, top),
                                                           "width": min(1280, right) - max(0, left), "height": bottom - top}))
    # leave the call so that nothing is left connected when the next picture is taken
    for pg in (mod, alex):
        try:
            pg.keyboard.press("Escape")
            pg.click("#voice-join-btn", timeout=3000)
        except Exception:
            pass



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# -- 1.21.0: My VODs, the player and the VOD settings ------------------------------------------------

VOD_STREAM = "Evening Build Stream"
_NOW = time.time()
VOD_DAYS = [time.strftime("%Y-%m-%d", time.gmtime(_NOW - 86400 * n)) for n in (2, 1)]   # the two latest days, in UTC
VOD_DAY = VOD_DAYS[0]
_EVENING = lambda days: (int(_NOW // 86400) - days) * 86400 + 20 * 3600     # 20:00 UTC of that day
VOD_CHUNKS = [  # name, size in bytes, modified (UTC seconds)
    (f"{VOD_STREAM}/{VOD_DAYS[0]}/chunk_000.mkv", 41_873_920, _EVENING(2)),
    (f"{VOD_STREAM}/{VOD_DAYS[0]}/chunk_001.mkv", 43_190_784, _EVENING(2) + 300),
    (f"{VOD_STREAM}/{VOD_DAYS[0]}/chunk_002.mkv", 40_411_136, _EVENING(2) + 600),
    (f"{VOD_STREAM}/{VOD_DAYS[0]}/chunk_003.mkv", 22_020_096, _EVENING(2) + 900),
    (f"{VOD_STREAM}/{VOD_DAYS[1]}/chunk_000.mkv", 44_040_192, _EVENING(1)),
    (f"{VOD_STREAM}/{VOD_DAYS[1]}/chunk_001.mkv", 42_991_616, _EVENING(1) + 300),
]
# the text the disk guard stores for a recording it stopped (server.py builds it from vod_staging.guard_verdict)
VOD_GUARD = {"kind": "stopped", "code": "low_free_space", "stream_name": VOD_STREAM,
             "at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(_NOW - 1500)),
             "message": f"The VOD recording of '{VOD_STREAM}' was stopped: only 640 MB free in the VOD staging folder (needs 1.0 GB)"}


def vod_list_body(guard=None) -> str:
    return json.dumps({"files": [{"name": n, "size": z, "modified": m} for n, z, m in VOD_CHUNKS],
                       "path": "/srv/vods", "recording_guard": guard,
                       "playback": {"enabled": True, "message": None}})


def make_test_clip(path: Path) -> None:
    """A 24 second synthetic test pattern (H.264 8 bit 4:2:0 with AAC, index first) written into the stage."""
    import subprocess
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=960x540:rate=25:duration=24",
                    "-f", "lavfi", "-i", "sine=frequency=440:duration=24", "-c:v", "libx264", "-preset", "veryfast",
                    "-crf", "30", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "48k", "-movflags", "+faststart", str(path)],
                   check=True, timeout=120)


def route_vods(ctx, guard=None, clip: bytes | None = None) -> None:
    """Answer the VOD routes of one browser context with made-up data (the staged server has no storage)."""
    import re as _re
    ctx.route(_re.compile(r"^https://[^/]+/api/vods(\?.*)?$"), lambda r: r.fulfill(
        status=200, content_type="application/json", body=vod_list_body(guard)))
    ctx.route("**/cdn.jsdelivr.net/**", lambda r: r.abort())      # hls.js: nothing leaves the machine

    def play(route):
        if clip is None:
            route.fulfill(status=404, content_type="application/json", body="{}")
            return
        rng = route.request.headers.get("range", "")
        m = _re.match(r"bytes=(\d+)-(\d*)$", rng)
        size = len(clip)
        if not m:
            route.fulfill(status=200, headers={"Content-Type": "video/mp4", "Accept-Ranges": "bytes"}, body=clip)
            return
        a = int(m.group(1))
        b = min(int(m.group(2)) if m.group(2) else size - 1, size - 1)
        route.fulfill(status=206, body=clip[a:b + 1], headers={
            "Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Range": f"bytes {a}-{b}/{size}"})
    ctx.route("**/api/vods/play/**", play)


def save_my_vods(s, page, name: str) -> None:
    """The My VODs tab with the tab bar above it (the stats and the activity card of the dashboard are cropped away)."""
    from io import BytesIO
    from PIL import Image
    top = page.locator("#tab-btn-services").locator("xpath=..").bounding_box()["y"] - 12
    body = page.locator("#tab-my-vods").bounding_box()
    height = min(body["y"] + body["height"] + 16, 1320) - top
    raw = page.screenshot(clip={"x": 240, "y": top, "width": 1040, "height": height})
    s.write(name, Image.open(BytesIO(raw)).convert("RGB"))


def my_vods_page(s, guard=None):
    ctx = s.context("alex", viewport={"width": 1280, "height": 1320})
    route_vods(ctx, guard)
    page = s.open(ctx, "/", ".service-card, .stat-card")
    page.evaluate("switchTab('my-vods')")
    page.wait_for_selector(".vod-play-btn", state="attached", timeout=15000)
    # the buttons of a row show while the pointer is over it (the portal's own style): point at one chunk
    page.hover(".vod-file-row >> nth=1")
    page.wait_for_selector(".vod-file-row:hover .vod-play-btn", state="visible", timeout=5000)
    page.wait_for_timeout(500)
    return page


@shot("my-vods")
def _my_vods(s):
    page = my_vods_page(s)
    assert_clean(s, page, "my-vods")
    save_my_vods(s, page, "my-vods")


@shot("my-vods-notice")
def _my_vods_notice(s):
    page = my_vods_page(s, VOD_GUARD)
    page.wait_for_selector("#vods-guard-notice", state="visible", timeout=10000)
    assert_clean(s, page, "my-vods-notice")
    save_my_vods(s, page, "my-vods-notice")


@shot("vod-player")
def _vod_player(s):
    from urllib.parse import quote
    clip_path = s.stage.dir / "demo_clip.mp4"
    make_test_clip(clip_path)
    ctx = s.context("alex", viewport={"width": 1280, "height": 860})
    route_vods(ctx, None, clip_path.read_bytes())
    name = f"{VOD_STREAM}/{VOD_DAY}/chunk_001.mkv"
    page = s.open(ctx, "/vods/play?name=" + quote(name), "#vp-video", settle=500)
    ready = True
    try:
        page.wait_for_function("() => { const v = document.getElementById('vp-video'); "
                               "return v.style.display !== 'none' && v.readyState >= 2 && v.videoWidth > 0; }", timeout=25000)
        # stop on a frame, the way a paused player looks
        page.evaluate("async () => { const v = document.getElementById('vp-video'); v.pause(); v.currentTime = 9.0;"
                      " await new Promise(r => v.addEventListener('seeked', r, {once: true})); }")
        page.wait_for_timeout(600)
    except Exception:
        ready = False
        print("NOTE vod-player: the browser did not decode a frame (no H.264?); the page is shown without one", file=sys.stderr)
    page.wait_for_function("() => document.getElementById('vp-pos').textContent.length > 0", timeout=10000)
    assert_clean(s, page, "vod-player")
    s.save("vod-player", page)
    s.vod_player_frame = ready


@shot("admin-vod-settings")
def _admin_vod_settings(s):
    page = admin_page(s, "settings", "#ret-vod-min-free")
    # only the four VOD fields of the Data Retention card: the other fields of the grid are hidden for the picture
    page.evaluate("""() => {
        const keep = ['ret-vod-min-free', 'ret-vod-backlog', 'ret-vod-play-cache', 'ret-vod-orphan-age']
            .map((id) => document.getElementById(id).parentElement);
        const grid = keep[0].parentElement;
        Array.from(grid.children).forEach((c) => { if (!keep.includes(c)) c.style.display = 'none'; });
        const sibs = Array.from(document.getElementById('retention-config').children);
        sibs.forEach((c) => { if (c !== grid && !c.contains(grid)) c.style.display = 'none'; });
    }""")
    page.wait_for_timeout(300)
    assert_clean(s, page, "admin-vod-settings")
    s.save("admin-vod-settings", page.locator("#retention-config").locator("xpath=ancestor::div[contains(@class,'admin-card')][1]"))


# -- 1.22.0: dashboard organising, health dots, announcements, maintenance, request and reference IDs ----

import contextlib
import re
import socket
import sqlite3
import threading

REF_RE = re.compile(r"\b[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}\b")


def api(page, method: str, path: str, body=None):
    """A call of the signed-in browser session (its cookie and address), made from a page of the demo host."""
    res = page.evaluate(
        """async ([m, p, b]) => { const r = await fetch(p, {method: m, headers: {'Content-Type': 'application/json'},
            body: b === null ? undefined : JSON.stringify(b)}); let j = null; try { j = await r.json(); } catch (e) {}
            return [r.status, j]; }""", [method, path, body])
    return res[0], res[1]


def api_ok(page, method: str, path: str, body=None, ok=(200, 201, 204)):
    status, data = api(page, method, path, body)
    if status not in ok:
        raise Fail(f"{method} {path} -> {status} {data}")
    return data


def api_page(s, ctx):
    page = ctx.new_page()
    page.goto(f"{s.stage.base}/about")
    page.wait_for_load_state("domcontentloaded")
    return page


def stage_db(s) -> sqlite3.Connection:
    return sqlite3.connect(str(s.stage.dir / "portal.db"), timeout=30)


DEMO_FILING = {
    # name: (folder, tags, pinned)
    "Build server": ("Servers", ["linux", "build"], True),
    "Inventory database": ("Servers", ["database"], True),
    "Workshop desktop": ("Home lab", ["desktop", "workshop"], False),
    "Office PC": ("Home lab", ["desktop"], False),
    "Metrics dashboard": ("Media and metrics", ["web", "grafana"], False),
    "Media library": ("Media and metrics", ["web", "media"], False),
}
# opened oldest first, so the newest ends first in the Recently used row
DEMO_OPENED = ["Metrics dashboard", "Workshop desktop", "Build server"]


def organised_alex(s) -> dict:
    """Alex files his demo connections (folders, tags, pins) and opens four of them. Once per run."""
    if getattr(s, "_organised", None):
        return s._organised
    ctx = s.context("alex")
    page = api_page(s, ctx)
    listing = api_ok(page, "GET", "/api/connections")
    by_name = {c["name"]: c["id"] for c in (listing.get("connections") if isinstance(listing, dict) else listing)}
    for name, (folder, tags, pinned) in DEMO_FILING.items():
        api_ok(page, "PUT", f"/api/connections/{by_name[name]}/prefs", {"folder": folder, "tags": tags, "pinned": pinned})
    for name in DEMO_OPENED:
        api_ok(page, "GET", f"/api/connections/{by_name[name]}/connect")
        page.wait_for_timeout(1100)
    page.close()
    s._organised = by_name
    return by_name


class _Listener:
    """A TCP listener on 127.0.0.1 that accepts and closes at once: the target of an 'up' demo connection."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.3)
        self.port = self.sock.getsockname()[1]
        self.stopped = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stopped:
            try:
                conn, _ = self.sock.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return

    def stop(self):
        self.stopped = True
        self.thread.join(timeout=3)
        self.sock.close()


def closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def put_setting(db, key: str, value) -> None:
    if value is None:
        db.execute("DELETE FROM settings WHERE key = ?", (key,))
    else:
        db.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    db.commit()


@contextlib.contextmanager
def health_dots(s, ctx_page, by_name: dict):
    """Switch the health checks on for three demo connections through the stage's own state and wait until the
    real status route answers up, up and down. Yields {connection id: (demo host, demo port)} for the rewrite of the
    cards. Everything is put back afterwards."""
    up_names, down_name = ("Build server", "Workshop desktop"), "Inventory database"
    listener = _Listener()
    down_port = closed_port()
    db = stage_db(s)
    keys = ("connection_health_enabled", "connection_health_interval", "stage_health_target_ports")
    saved = {k: (db.execute("SELECT value FROM settings WHERE key = ?", (k,)).fetchone() or [None])[0] for k in keys}
    originals = {}
    try:
        for name in up_names + (down_name,):
            row = db.execute("SELECT host, port FROM user_connections WHERE uuid = ?", (by_name[name],)).fetchone()
            originals[by_name[name]] = (row[0], row[1])
            port = listener.port if name in up_names else down_port
            db.execute("UPDATE user_connections SET host = '127.0.0.1', port = ? WHERE uuid = ?", (port, by_name[name]))
        db.commit()
        put_setting(db, "stage_health_target_ports", f"{listener.port},{down_port}")
        put_setting(db, "connection_health_enabled", "1")
        want = {by_name[n]: "up" for n in up_names}
        want[by_name[down_name]] = "down"
        deadline = time.monotonic() + 40
        got = {}
        while time.monotonic() < deadline:
            status, body = api(ctx_page, "GET", "/api/connections/status")
            got = {k: (body or {}).get(k, {}).get("status") for k in want} if status == 200 else {}
            if got == want:
                break
            ctx_page.wait_for_timeout(1000)
        else:
            raise Fail(f"the health checks did not reach {want}: {got}")
        yield {by_name[n]: originals[by_name[n]] for n in up_names + (down_name,)}
    finally:
        for uuid_, (host, port) in originals.items():
            db.execute("UPDATE user_connections SET host = ?, port = ? WHERE uuid = ?", (host, port, uuid_))
        db.commit()
        for k, v in saved.items():
            put_setting(db, k, v)
        db.close()
        listener.stop()


def rewrite_card_hosts(s, ctx, rewrite: dict) -> None:
    """The three probed demo connections point at 127.0.0.1 inside the stage only: in this browser session the list
    answer shows them under their fictional names again (host and port only; the status route is untouched)."""
    def handler(route):
        # the route's own request does not use the browser's host rule: it goes to the loopback address directly
        resp = route.fetch(url=route.request.url.replace(s.stage.base, s.stage.direct))
        try:
            data = resp.json()
        except Exception:
            route.fulfill(response=resp)
            return
        items = data.get("connections") if isinstance(data, dict) else data
        for item in items or []:
            if item.get("id") in rewrite:
                item["host"], item["port"] = rewrite[item["id"]]
        route.fulfill(response=resp, body=json.dumps(data), headers={**resp.headers, "content-type": "application/json"})
    ctx.route(re.compile(r".*/api/connections(\?.*)?$"), handler)


def connections_tab(page) -> None:
    page.click("#tab-btn-my-connections")
    page.wait_for_selector("#conn-organiser:not([hidden])", timeout=15000)
    page.wait_for_selector(".conn-folder", timeout=15000)
    page.wait_for_timeout(500)


def organise_page(s, ctx, with_dots: bool = False):
    page = s.open(ctx, "/", "#tab-btn-my-connections")
    connections_tab(page)
    if with_dots:
        page.wait_for_selector(".conn-health-dot", timeout=15000)
    return page


@shot("dashboard-organise")
def _dashboard_organise(s):
    by_name = organised_alex(s)
    ctx = s.context("alex", viewport={"width": 1280, "height": 1240})
    helper = api_page(s, ctx)
    with health_dots(s, helper, by_name) as rewrite:
        rewrite_card_hosts(s, ctx, rewrite)
        page = organise_page(s, ctx, with_dots=True)
        dots = page.evaluate("() => Array.from(document.querySelectorAll('.conn-health-dot')).map((d) => d.getAttribute('data-conn-health'))")
        if "up" not in dots or "down" not in dots:
            raise Fail(f"the dashboard drew the dots {dots}, not an up and a down one")
        # two of the three folders are collapsed (the caret of a folder head), the first stays open
        for folder in ("Home lab", "Media and metrics"):
            page.click(f'.conn-folder-head[data-folder="{folder}"]')
        page.focus("#conn-filter")
        page.evaluate("() => window.scrollTo(0, document.querySelector('#tab-btn-my-connections').getBoundingClientRect().top + window.scrollY - 90)")
        page.wait_for_timeout(400)
        assert_clean(s, page, "dashboard-organise")
        s.save("dashboard-organise", page)


@shot("dashboard-organise-dialog")
def _dashboard_organise_dialog(s):
    organised_alex(s)
    ctx = s.context("alex")
    page = organise_page(s, ctx)
    # the folder and tags dialog of one card
    page.evaluate("""() => { const card = Array.from(document.querySelectorAll('.connection-card'))
        .find((c) => /Workshop desktop/.test(c.textContent)); card.querySelector('button[title="Folder and tags"]').click(); }""")
    page.wait_for_selector("#conn-organise-modal", state="visible", timeout=10000)
    page.wait_for_timeout(500)
    assert_clean(s, page, "dashboard-organise-dialog")
    s.save("dashboard-organise-dialog", page)


@contextlib.contextmanager
def announcement(s, body: str, level: str = "warning"):
    ctx = s.admin_ctx
    page = api_page(s, ctx)
    made = api_ok(page, "POST", "/api/admin/announcements", {"level": level, "body": body})
    ident = (made.get("announcement") or made).get("id")
    try:
        yield ident
    finally:
        try:
            api_ok(page, "DELETE", f"/api/admin/announcements/{ident}")
        finally:
            page.close()


ANNOUNCEMENT_TEXT = ("**Planned maintenance:** the relay host gets its monthly updates on Saturday from 02:00 to 03:00 UTC. "
                     "Streams may drop for a few minutes. Details in the [schedule](https://example.org/schedule).")


@shot("announcement-banner")
def _announcement_banner(s):
    with announcement(s, ANNOUNCEMENT_TEXT):
        page = s.open(s.context("alex"), "/chat", ".announce", settle=900)
        assert_clean(s, page, "announcement-banner")
        s.save("announcement-banner", page)


@contextlib.contextmanager
def maintenance_fixture(s):
    """A connection of the administrator, shared with alex, in maintenance until a full hour from now with a
    message; deleted afterwards. Yields its id."""
    from datetime import datetime, timedelta, timezone
    admin_page_ = api_page(s, s.admin_ctx)
    until = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    made = api_ok(admin_page_, "POST", "/api/connections", {
        "name": "Team wiki", "type": "grafana", "host": "wiki.example.org", "port": 3000, "config": {}})
    ident = (made.get("connection") or made).get("id")
    try:
        api_ok(admin_page_, "POST", f"/api/connections/{ident}/shares", {"usernames": ["alex"], "expires_in": "30d"})
        api_ok(admin_page_, "PUT", f"/api/connections/{ident}", {
            "name": "Team wiki", "type": "grafana", "host": "wiki.example.org", "port": 3000,
            "maintenance": True, "maintenance_until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "maintenance_message": "Moving the wiki to a new disk. Pages are read-only elsewhere until then."})
        yield ident
    finally:
        try:
            api_ok(admin_page_, "DELETE", f"/api/connections/{ident}")
        finally:
            admin_page_.close()


@shot("maintenance-page")
def _maintenance_page(s):
    with maintenance_fixture(s) as ident:
        ctx = s.context("alex", scale=2)
        page = ctx.new_page()
        response = page.goto(f"{s.stage.base}/proxy/{ident}/")
        page.wait_for_load_state("networkidle")
        if response.status != 503:
            raise Fail(f"the maintenance page answered {response.status}, not 503")
        page.wait_for_function("() => /until|maintenance/i.test(document.body.textContent)", timeout=10000)
        page.wait_for_timeout(500)
        assert_clean(s, page, "maintenance-page")
        save_cropped(s, "maintenance-page", page, 640, 280)


@shot("upstream-error-page")
def _upstream_error_page(s):
    ctx = s.context("alex", scale=2)
    page = ctx.new_page()
    response = page.goto(f"{s.stage.base}/search/")
    page.wait_for_load_state("networkidle")
    rid = response.headers.get("x-request-id", "")
    if response.status != 503 or not rid:
        raise Fail(f"/search/ answered {response.status} with request id {rid!r}")
    if rid not in page.inner_text("body"):
        raise Fail("the request ID of the answer is not on the page")
    assert_clean(s, page, "upstream-error-page")
    # the page reloads itself after its countdown: the picture is taken at once
    save_cropped(s, "upstream-error-page", page, 640, 260)


def save_cropped(s, name: str, page, width: int, height: int) -> None:
    """A page that is only a few lines of text: the top-left part of it, at twice the resolution."""
    from io import BytesIO
    from PIL import Image
    raw = page.screenshot(clip={"x": 0, "y": 0, "width": width, "height": height})
    s.write(name, Image.open(BytesIO(raw)).convert("RGB"))


def block_reference(s) -> str:
    """The reference a client at the already blocked documentation address sees (read from the page itself)."""
    if getattr(s, "_block_ref", None):
        return s._block_ref
    ctx = s.context(None, address="198.51.100.77", scale=2)
    page = ctx.new_page()
    response = page.goto(f"{s.stage.base}/", wait_until="domcontentloaded")
    page.wait_for_timeout(500)
    if response.status != 403:
        raise Fail(f"the blocked address got {response.status}, not 403")
    m = REF_RE.search(page.inner_text("body"))
    if not m:
        raise Fail("no reference on the block page")
    s._block_ref = m.group(0)
    s._block_page = page
    return s._block_ref


@shot("block-page")
def _block_page(s):
    block_reference(s)
    page = s._block_page
    assert_clean(s, page, "block-page")
    save_cropped(s, "block-page", page, 480, 170)


@shot("admin-block-lookup")
def _admin_block_lookup(s):
    ref = block_reference(s)
    page = admin_page(s, "system", "#tab-system")
    page.evaluate("showSysSubTab('network')")
    page.wait_for_selector("#block-ref-input", state="visible", timeout=10000)
    page.fill("#block-ref-input", ref)
    page.click("#block-ref-go")
    page.wait_for_function("() => document.getElementById('block-ref-result').textContent.trim().length > 0", timeout=10000)
    page.wait_for_timeout(500)
    # only the lookup: everything above its heading in the same section is hidden for the picture
    page.evaluate("""() => {
        const h = Array.from(document.querySelectorAll('h3')).find((x) => /Reference lookup/.test(x.textContent));
        const section = h.parentElement;
        for (const c of Array.from(section.children)) { if (c === h) break; c.style.display = 'none'; }
        section.id = 'shot-scope';
    }""")
    text = page.inner_text("#block-ref-result")
    if "198.51.100.77" not in text:
        raise Fail(f"the lookup did not show the blocked address: {text[:120]!r}")
    assert_clean(s, page, "admin-block-lookup", "#shot-scope")
    s.save("admin-block-lookup", page.locator("#block-ref-input").locator("xpath=ancestor::div[contains(@class,'sys-net-section')][1]"))


@shot("admin-maintenance")
def _admin_maintenance(s):
    with maintenance_fixture(s):
        page = admin_page(s, "settings", "#maintenance-card")
        page.wait_for_function("() => document.getElementById('maintenance-conns').textContent.trim().length > 0", timeout=10000)
        page.fill("#maint-message", "Planned work on the proxy host.")
        page.wait_for_timeout(300)
        assert_clean(s, page, "admin-maintenance")
        s.save("admin-maintenance", page.locator("#maintenance-card"))


@shot("admin-announcements")
def _admin_announcements(s):
    with announcement(s, ANNOUNCEMENT_TEXT):
        page = admin_page(s, "settings", "#announcements-card")
        page.get_by_role("button", name="New announcement").click()
        page.wait_for_selector("#announce-form-slot textarea", timeout=10000)
        page.fill("#announce-form-slot textarea", "Heads up: the chat server restarts at 03:00 UTC tonight.")
        page.wait_for_timeout(400)
        assert_clean(s, page, "admin-announcements")
        s.save("admin-announcements", page.locator("#announcements-card"))


# -- 1.23.0: stream schedule, calendar link, saved messages ----------------------

def schedule_local(delta_seconds: int, tz: str) -> str:
    """A wall-clock start `delta_seconds` from now in zone `tz`, rounded up to the half hour, as the schedule routes take it."""
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo
    t = datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)
    t = t.replace(second=0, microsecond=0) + timedelta(minutes=(30 - t.minute % 30) % 30)
    return t.astimezone(ZoneInfo(tz)).strftime("%Y-%m-%dT%H:%M")


def next_weekday_local(weekday: int, hour: int, tz: str) -> str:
    """The next `weekday` (Monday 0) at `hour`:00 wall-clock time in `tz`, at least a day away."""
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo
    z = ZoneInfo(tz)
    t = datetime.now(timezone.utc).astimezone(z).replace(hour=hour, minute=0, second=0, microsecond=0, tzinfo=None) + timedelta(days=1)
    while t.weekday() != weekday:
        t += timedelta(days=1)
    return t.strftime("%Y-%m-%dT%H:%M")


def seeded_schedule(s) -> dict:
    """Schedule entries of the demo streams, through the real routes, once per run: a weekly slot for sam's
    (offline) stream, river's and jordan's slots, two slots of alex's own stream, and alex's Interested mark on
    river's slot. Returns the ids the pictures need."""
    if getattr(s, "_schedule", None):
        return s._schedule
    gid = s.info["golive"]
    alex_stream = s.info["streams"]["public"]
    out: dict = {"sam": gid["sam"], "alex": alex_stream}
    plan = [
        ("sam", gid["sam"], {"title": "Monthly questions about the portal", "start": schedule_local(27 * 3600, "America/New_York"),
                              "tz": "America/New_York", "duration_min": 60, "recurrence": "weekly"}),
        ("river", gid["river"], {"title": "Saturday sketch hour", "start": next_weekday_local(5, 18, "Europe/London"),
                                  "tz": "Europe/London", "duration_min": 90, "recurrence": "weekly"}),
        ("jordan", gid["jordan"], {"title": "Capacitor swap on a console", "start": schedule_local(50 * 3600, "Europe/Berlin"),
                                    "tz": "Europe/Berlin", "duration_min": 120, "recurrence": None}),
        ("alex", alex_stream, {"title": "Friday game night", "start": next_weekday_local(4, 21, "Europe/Berlin"),
                                "tz": "Europe/Berlin", "duration_min": 180, "recurrence": "weekly"}),
        ("alex", alex_stream, {"title": "Chess endgames, one-off special", "start": schedule_local(5 * 86400, "Europe/Berlin"),
                                "tz": "Europe/Berlin", "duration_min": 90, "recurrence": None}),
    ]
    for owner, stream_id, body in plan:
        page = api_page(s, s.context(owner))
        api_ok(page, "POST", f"/api/streams/{stream_id}/schedule", body)
        page.close()
    alex_page = api_page(s, s.context("alex"))
    upcoming = api_ok(alex_page, "GET", "/api/streams/schedule/upcoming?limit=20")["occurrences"]
    river = next((o for o in upcoming if o["stream_id"] == gid["river"]), None)
    if river is None:
        raise Fail("river's slot is not in alex's upcoming list")
    api_ok(alex_page, "POST", f"/api/streams/{river['stream_id']}/schedule/{river['entry_id']}/rsvp/{river['start']}")
    alex_page.close()
    s._schedule = out
    return out


@shot("watch-schedule")
def _watch_schedule(s):
    # the offline watch page of sam's stream as alex: the next slot, its countdown and the Interested toggle
    ids = seeded_schedule(s)
    page = s.open(s.context("alex"), f"/watch/{ids['sam']}", ".schedule-countdown", settle=1800)
    page.wait_for_selector(".schedule-interested", timeout=15000)
    assert_clean(s, page, "watch-schedule")
    s.save("watch-schedule", page)


@shot("streams-upcoming")
def _streams_upcoming(s):
    seeded_schedule(s)
    page = s.open(s.context("alex"), "/streams", ".schedule-strip .schedule-card", settle=1800)
    assert_clean(s, page, "streams-upcoming")
    # the top of the page only: the search box and the Upcoming strip (the cards below it are the older streams picture)
    s.write_bytes("streams-upcoming", page.screenshot(clip={"x": 0, "y": 0, "width": 1280, "height": 372}))


@shot("schedule-editor")
def _schedule_editor(s):
    seeded_schedule(s)
    ctx = s.context("alex", viewport={"width": 1280, "height": 2400})
    page = s.open(ctx, "/", ".stat-card")
    page.evaluate("switchTab('my-streams')")
    page.wait_for_selector(".stream-card", timeout=15000)
    page.wait_for_timeout(800)
    page.locator(".stream-card", has_text="Friday game night").get_by_role("button", name="Manage").first.click()
    page.wait_for_selector("#stream-details-modal .info-section", state="visible")
    page.evaluate("""() => document.querySelectorAll('#stream-details-modal .modal-content, #stream-details-modal .modal-body')
        .forEach(el => { el.style.maxHeight = 'none'; el.style.overflow = 'visible'; })""")
    page.wait_for_selector("#stream-schedule-mount .schedule-form", timeout=15000)
    page.wait_for_timeout(800)
    assert_clean(s, page, "schedule-editor", "#stream-schedule-mount")
    s.save("schedule-editor", page.locator("#stream-schedule-mount").locator("xpath=.."))


@shot("calendar-link")
def _calendar_link(s):
    # the member's own link, made through the real route; the block is shown after a reload, which is the state
    # the portal keeps (the address cannot be shown again), so no token appears in the picture
    ctx = s.context("alex", viewport={"width": 1280, "height": 1300})
    pre = api_page(s, ctx)
    api_ok(pre, "POST", "/api/me/schedule-feed")
    pre.close()
    page = s.open(ctx, "/", ".stat-card")
    page.evaluate("showProfileModal()")
    page.wait_for_selector("#calendar-feed-settings .schedule-feed-warning", state="visible", timeout=15000)
    page.get_by_role("heading", name="Calendar link for stream schedules").evaluate("el => el.scrollIntoView({block: 'start'})")
    page.wait_for_timeout(600)
    text = page.locator("#calendar-feed-settings").inner_text()
    if "sf_" in text or "http" in text:
        raise Fail("the calendar link block shows an address")
    assert_clean(s, page, "calendar-link", "#calendar-feed-settings")
    head = page.get_by_role("heading", name="Calendar link for stream schedules").bounding_box()
    body = page.locator("#calendar-feed-settings").bounding_box()
    pad = 24
    clip = {"x": body["x"] - pad, "y": head["y"] - pad, "width": body["width"] + 2 * pad,
            "height": body["y"] + body["height"] - head["y"] + 2 * pad}
    s.write_bytes("calendar-link", page.screenshot(clip=clip))


def saved_demo(s) -> dict:
    """Three saved messages of alex, once per run: the one saved first is a message he posts himself and deletes
    afterwards (the real delete frame), so the list shows it as no longer available; the second has a reminder
    tomorrow at 9:00; the third is plain. The newest saved comes first in the list. Messages of the seeded talk
    (the general channel) are referred to by their text."""
    if getattr(s, "_saved", None):
        return s._saved
    from datetime import datetime, timedelta, timezone
    page = chat_page(s, "alex")
    mine = "Draft slide order for the meetup: invite code, username, done"
    page.fill("#chat-input", mine)
    page.evaluate("sendMessage()")
    page.wait_for_selector(f".message:has-text('{mine}')", timeout=15000)
    gone_id = int(page.locator(f".message:has-text('{mine}')").last.get_attribute("data-message-id"))

    def message_id(text: str) -> int:
        return int(page.locator(f".message:has-text('{text}')").first.get_attribute("data-message-id"))
    remind_id = message_id("Newcomer question from my neighbour")
    plain_id = message_id("No rush, we will post notes afterwards")
    for mid in (gone_id, remind_id, plain_id):
        api_ok(page, "POST", "/api/saved", {"kind": "channel", "message_id": mid})
    listing = api_ok(page, "GET", "/api/saved?limit=30")["items"]
    entry = next(i for i in listing if i.get("message_id") == remind_id)
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
    api_ok(page, "PUT", f"/api/saved/{entry['id']}/remind", {"remind_at": tomorrow.strftime("%Y-%m-%dT%H:%M:%SZ")})
    page.evaluate("(id) => ws.send(JSON.stringify({type: 'delete', message_id: id}))", gone_id)
    page.wait_for_function(f"() => !document.querySelector('.message[data-message-id=\"{gone_id}\"]')", timeout=15000)
    page.wait_for_timeout(500)
    page.close()
    s._saved = {"gone": gone_id, "remind": remind_id, "plain": plain_id}
    return s._saved


@shot("chat-message-menu")
def _chat_message_menu(s):
    # the message menu with Save message and Remind me..., on a message next to one alex already saved
    ids = saved_demo(s)
    page = chat_page(s, "alex")
    page.wait_for_selector(f".message[data-message-id='{ids['plain']}'] .saved-badge", timeout=15000)
    page.evaluate(f"""() => document.querySelector('.message[data-message-id="{ids['plain']}"]').scrollIntoView({{block: 'center'}})""")
    page.wait_for_timeout(500)
    target = page.locator(".message", has_text="I will join if I can get the kids to bed").first
    target.scroll_into_view_if_needed()
    page.evaluate("window.scrollTo(0, 0)")
    target.click(button="right", position={"x": 640, "y": 14})
    page.wait_for_selector("#message-context-menu.show", timeout=5000)
    page.wait_for_timeout(500)
    assert_clean(s, page, "chat-message-menu")
    s.save("chat-message-menu", page)


@shot("saved-view")
def _saved_view(s):
    saved_demo(s)
    page = chat_page(s, "alex")
    page.click("#saved-open-btn")
    page.wait_for_selector(".saved-panel .saved-list > *", timeout=15000)
    page.wait_for_function("() => document.querySelectorAll('.saved-panel .saved-list > *').length >= 3", timeout=15000)
    page.wait_for_timeout(700)
    text = page.locator(".saved-panel").inner_text()
    if "No longer available" not in text or "Reminder" not in text:
        raise Fail("the Saved view does not show a reminder and a no longer available entry")
    assert_clean(s, page, "saved-view", ".saved-panel")
    s.save("saved-view", page)



class _Terminated(BaseException):
    pass


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Take the README screenshots from a staged demo instance.")
    p.add_argument("--chromium", default="/usr/bin/chromium", help="path of the Chromium executable (default /usr/bin/chromium)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port of the staged instance (default {DEFAULT_PORT})")
    p.add_argument("--out", type=Path, default=REPO / "docs" / "screenshots", help="directory for the PNG files")
    p.add_argument("--only", metavar="NAME[,NAME]", help="take only these pictures (the demo data is still seeded)")
    p.add_argument("--list", action="store_true", help="print the picture names and exit")
    p.add_argument("--no-optimize", action="store_true", help="do not run PNG optimisation")
    args = p.parse_args(argv)
    if not (1024 <= args.port <= 65535) or args.port == 443:
        p.error("--port must be an unprivileged port (1024-65535)")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.list:
        print("\n".join(SHOTS))
        return 0
    # the security events list is newest first: take it before the other pictures add sign-ins to it
    wanted = sorted(SHOTS, key=lambda n: n != "admin-security-events")
    if args.only:
        wanted = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in wanted if n not in SHOTS]
        if unknown:
            print(f"unknown picture name(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
    try:
        from playwright.sync_api import sync_playwright
        __import__("PIL.Image")
    except ImportError as e:
        print(f"missing module ({e}): see the top of this file for the environment it needs", file=sys.stderr)
        return 2
    if not Path(args.chromium).exists():
        print(f"{args.chromium} does not exist", file=sys.stderr)
        return 2

    def _terminate(signum, _frame):
        raise _Terminated()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _terminate)

    stage = Stage(args.port)
    rc = 0
    failed: list = []
    try:
        stage.start()
        info = asyncio.run(seed_everything(stage))
        print("demo data is in place", flush=True)
        with sync_playwright() as pw:
            shooter = Shooter(pw, stage, args.out, args.chromium, info, not args.no_optimize)
            try:
                for name in wanted:
                    if name != "admin-security-events" and not shooter.presence_pages:
                        shooter.start_presence()
                    try:
                        SHOTS[name](shooter)
                    except Exception as e:
                        failed.append(name)
                        print(f"FAILED {name}: {type(e).__name__}: {str(e).splitlines()[0][:200]}", file=sys.stderr)
                        traceback.print_exc(limit=3)
            finally:
                shooter.close()
        print(f"{len(wanted) - len(failed)} pictures written, {len(failed)} failed")
        rc = 1 if failed else 0
    except (KeyboardInterrupt, _Terminated):
        print("\ninterrupted", file=sys.stderr)
        rc = 130
    except Fail as e:
        print(f"FAIL {e}", file=sys.stderr)
        if stage.server is not None:
            print(stage.server.log_tail(15), file=sys.stderr)
        rc = 2
    except Exception:
        traceback.print_exc()
        rc = 2
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        stage.stop()
    return rc


async def seed_golive(stage: Stage, clients: dict, info_streams: dict) -> dict:
    """Streams of other members, follows, and two streams that go live (1.16.0).

    The go-live is the real path: the MediaMTX publish hook POST /api/stream/auth, called from
    loopback with the stream's own key (there is no MediaMTX, OBS or video: the stream is only
    marked live). The announce channel is `general`, so the go-live cards appear in the chat
    picture. Run after the chat messages were given their times, so the cards are the newest."""
    admin, alex = clients[ADMIN_NAME], clients["alex"]
    chans = {c["name"]: c["id"] for c in (await admin.api("GET", "/api/chat/channels"))["channels"]}
    await admin.api("PUT", "/api/settings/permissions", {"stream_announce_channel_id": chans["general"]})

    made = {}
    for owner, name, desc, game in [
        ("river", "Saturday sketch hour", "Pencil and ink, ask anything while I draw", "Digital painting"),
        ("jordan", "Retro console repairs", "Recapping a 90s console on the bench", "Hardware repair"),
        ("sam", "Community Q and A", "Monthly questions about the portal", "Just chatting"),
    ]:
        r = await clients[owner].api("POST", "/api/streams", {
            "name": name, "description": desc, "is_public": True, "game": game})
        made[owner] = r.get("stream") or r
    # alex's own stream (made in seed_operations) gets a game too, for the settings picture
    await alex.api("PUT", f"/api/streams/{info_streams['public']}", {"game": "Chess"})
    # alex follows two of them (the toggle shows Following), casey one
    await alex.api("PUT", f"/api/streams/{made['river']['id']}/follow")
    await alex.api("PUT", f"/api/streams/{made['sam']['id']}/follow")
    await clients["casey"].api("PUT", f"/api/streams/{made['jordan']['id']}/follow")

    hook = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False), timeout=aiohttp.ClientTimeout(total=30))
    try:
        for owner in ("river", "jordan"):
            key = made[owner]["stream_key"]
            r = await hook.post(f"{stage.direct}/api/stream/auth",
                                json={"action": "publish", "path": "live/" + key, "password": key, "ip": "127.0.0.1"})
            if r.status != 200:
                raise Fail(f"publish hook for {owner}'s stream answered {r.status}")
    finally:
        await hook.close()
    # the announcement runs in the background: wait for both cards in the announce channel
    for _ in range(40):
        msgs = (await alex.api("GET", f"/api/chat/channels/{chans['general']}/messages?limit=50")).get("messages", [])
        if len([m for m in msgs if m.get("message_type") == "stream_card"]) >= 2:
            break
        await asyncio.sleep(0.25)
    else:
        raise Fail("the go-live cards did not appear in the announce channel")
    watch = await seed_stream_chat(stage, clients, made["river"], info_streams["public"])
    return {"golive": {k: v["id"] for k, v in made.items()}, "watch": watch}


async def seed_stream_chat(stage: Stage, clients: dict, river_stream: dict, alex_stream_id: int) -> dict:
    """The stream chat controls (1.17.0): river's live stream gets a mod (casey, an ordinary
    member, so the badge reads Mod and not staff), talk in its own chat and one pinned message.
    alex's stream gets two mods for the settings window. The viewer count is made by the
    shooter (it needs the viewers' browsers to send the heartbeat)."""
    river, alex = clients["river"], clients["alex"]
    rid = river_stream["id"]
    detail = (await river.api("GET", f"/api/streams/{rid}")).get("stream") or {}
    chan = detail.get("chat_channel_id")
    if not chan:
        raise Fail("river's stream has no chat channel of its own")
    await river.api("POST", f"/api/streams/{rid}/mods", {"user_id": clients["casey"].user_id})
    await alex.api("POST", f"/api/streams/{alex_stream_id}/mods", {"user_id": clients["casey"].user_id})
    await alex.api("POST", f"/api/streams/{alex_stream_id}/mods", {"user_id": clients["jordan"].user_id})
    socks = {}
    for name in ("river", "casey", "jordan", "alex", "sam"):
        ch = Chat(clients[name])
        await ch.open()
        await ch.send(type="join", channel_id=chan)
        socks[name] = ch
    await asyncio.sleep(1.0)
    await socks["river"].say("Welcome in. Tonight I am inking the lighthouse from the sketch I posted last week.")
    await socks["jordan"].say("That linework is so clean, what pen is that?")
    pen = await socks["river"].say("A 0.3 fineliner, and a brush pen for the shadows.")
    await socks["alex"].say("Will you do the sea next?")
    rules = await socks["casey"].say("Reminder: questions are welcome, spoilers for the new comic are not.")
    await socks["sam"].say("Loving the colours so far.")
    mark = len(socks["river"].frames)
    await socks["river"].send(type="pin_message", message_id=rules)
    await socks["river"].wait_for("message_pinned", mark)
    for ch in socks.values():
        await ch.close()
    return {"stream_id": rid, "public_key": detail.get("public_key") or river_stream.get("public_key")}


async def seed_access_limits(stage: Stage, clients: dict, info: dict) -> dict:
    """Shares with end times and a few administrator API keys (1.18.0).

    Two shares of alex's SSH connection with different end times, and three keys of the
    administrator: one bound to a documentation network and used once from an address of it,
    one plain, and one that looks forgotten (backdated in the stage's own database, a temp
    file this script made, so that the Stale badge shows). Nothing here ever connects anywhere.
    """
    import sqlite3
    alex, admin = clients["alex"], clients[ADMIN_NAME]
    conn_id = info["ssh_connection"]
    await alex.api("POST", f"/api/connections/{conn_id}/shares", {"usernames": ["sam"], "expires_in": "7d"})
    await alex.api("POST", f"/api/connections/{conn_id}/shares", {"usernames": ["river"], "expires_in": "30d"})
    bound = await admin.api("POST", "/api/api-keys", {
        "name": "Nightly report", "scopes": "services:read", "expires_days": 90,
        "allowed_cidrs": ["203.0.113.0/24"]})
    await admin.api("POST", "/api/api-keys", {"name": "Status page", "scopes": "services:read", "expires_days": 30})
    await admin.api("POST", "/api/api-keys", {"name": "Old integration", "scopes": "services:read", "expires_days": 365})
    # the bound key is used once, from an address inside its network (the loopback peer is a trusted
    # proxy, so the header decides which address the portal records)
    used = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False), timeout=aiohttp.ClientTimeout(total=30),
                                 headers={"CF-Connecting-IP": "203.0.113.20", "User-Agent": "curl/8.5.0"})
    try:
        r = await used.get(f"{stage.direct}/api/services", headers={"Authorization": "Api-Key " + bound["key"]})
        if r.status != 200:
            raise Fail(f"the bound demo key was refused from its own network: {r.status}")
    finally:
        await used.close()
    db = sqlite3.connect(str(stage.dir / "portal.db"), timeout=30)
    try:
        db.execute("UPDATE api_keys SET created_at = datetime('now', '-120 days'), last_used_at = datetime('now', '-100 days'),"
                   " last_used_ip = '198.51.100.40', created_ip = '192.0.2.10' WHERE name = 'Old integration'")
        db.commit()
    finally:
        db.close()
    return {}


ANDROID_AGENT = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/126.0 Mobile Safari/537.36")
IPHONE_AGENT = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.5 Mobile/15E148 Safari/604.1")


def demo_push_keys() -> dict:
    """A throw-away subscription key pair (P-256 point and auth secret); nothing here ever reaches a push service."""
    import base64
    import os
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {"p256dh": b64(point), "auth": b64(os.urandom(16))}


async def seed_notifications(stage: Stage, clients: dict, info: dict) -> dict:
    """A notification level for alex, push devices with documentation-name endpoints, push.example.org allowed."""
    admin = clients[ADMIN_NAME]
    await admin.api("PUT", "/api/admin/push", {"allowed_hosts": ["push.example.org"]})
    await clients["alex"].api("PUT", f"/api/chat/channels/{info['projects']['id']}/notify", {"level": "all"})
    await clients["alex"].api("PUT", f"/api/chat/channels/{info['help']['id']}/notify", {"level": "mentions"})
    for who, agent in (("alex", ANDROID_AGENT), ("alex", IPHONE_AGENT), ("river", ANDROID_AGENT)):
        endpoint = f"https://push.example.org/send/demo-{who}-{abs(hash(agent)) % 100000}"
        await clients[who].api("POST", "/api/push/subscriptions",
                               {"endpoint": endpoint, "keys": demo_push_keys()}, headers={"User-Agent": agent})
    return {}


# ---------------------------------------------------------------------------
# Session recordings (1.20.0): made-up shell output, written into the stage's own folder
# ---------------------------------------------------------------------------

def demo_casts() -> list:
    """(user, connection name, kind, minutes ago, events) of the demo recordings. Every line is
    invented: a made-up host (example-host), a user called demo, a documentation address and a token
    that says it is not a secret. Events are (seconds, text); the player cuts long pauses anyway."""
    prompt = "\x1b[1;32mdemo@example-host\x1b[0m:\x1b[1;34m~\x1b[0m$ "
    long_session = [
        (0.2, prompt),
        (0.9, "ls\r\n"),
        (1.1, "notes.txt  reports  scripts\r\n" + prompt),
        (1.9, "cat notes.txt\r\n"),
        (2.1, "Weekly checklist\r\n  - rotate the demo logs\r\n  - update the example config\r\n  - ask about the spare disk\r\n" + prompt),
        (3.0, "echo $DEMO_TOKEN\r\n"),
        (3.2, "demo-token-not-a-secret-0000\r\n" + prompt),
        (4.1, "ping -c 2 192.0.2.50\r\n"),
        (4.4, "PING 192.0.2.50 (192.0.2.50) 56(84) bytes of data.\r\n"),
        (4.9, "64 bytes from 192.0.2.50: icmp_seq=1 ttl=64 time=0.41 ms\r\n"),
        (5.9, "64 bytes from 192.0.2.50: icmp_seq=2 ttl=64 time=0.38 ms\r\n"),
        (6.0, "\r\n--- 192.0.2.50 ping statistics ---\r\n2 packets transmitted, 2 received, 0% packet loss\r\n" + prompt),
        (7.0, "exit\r\n"),
        (7.2, "logout\r\n"),
    ]
    short_session = [
        (0.2, prompt), (0.8, "uptime\r\n"),
        (1.0, " 10:42:01 up 12 days,  3:14,  1 user,  load average: 0.08, 0.05, 0.01\r\n" + prompt),
        (1.8, "exit\r\n"),
    ]
    return [
        ("alex", "Build server", "ssh", 35, long_session),
        ("river", "Media box", "ssh", 140, short_session),
        ("admin", "Example lab shell", "terminal", 300, short_session),
        ("alex", "Build server", "ssh", 1500, short_session),
    ]


def cast_text(events: list, started: float) -> str:
    header = {"version": 2, "width": 100, "height": 20, "timestamp": int(started),
              "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
    lines = [json.dumps(header)]
    for t, text in events:
        lines.append(json.dumps([t, "o", text]))
    return "\n".join(lines) + "\n"


def seed_recordings(stage: Stage) -> dict:
    """Plain files (mode 0600) in the stage's recordings folder (0700) and one row each in its own database.
    A row has a duration, so it is a finished recording and the start-up sweep leaves it alone."""
    import os
    import sqlite3
    from datetime import datetime, timedelta, timezone
    folder = stage.dir / "recordings"
    folder.mkdir(mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    conn = sqlite3.connect(str(stage.dir / "portal.db"), timeout=30)
    ids = []
    try:
        for user, name, kind, ago, events in demo_casts():
            uid = conn.execute("SELECT id FROM users WHERE username = ?", (user,)).fetchone()[0]
            started = datetime.now(timezone.utc) - timedelta(minutes=ago)
            body = cast_text(events, started.timestamp())
            fname = f"rec_{uid}_{int(started.timestamp())}_{len(ids)}.cast"
            path = folder / fname
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            cur = conn.execute(
                "INSERT INTO recordings (user_id, service_id, filename, size, duration, created_at, connection_name, kind) "
                "VALUES (?, NULL, ?, ?, ?, ?, ?, ?)",
                (uid, fname, len(body.encode("utf-8")), events[-1][0], started.strftime("%Y-%m-%d %H:%M:%S"), name, kind))
            ids.append(cur.lastrowid)
        conn.commit()
    finally:
        conn.close()
    return {"recordings": ids}


async def seed_everything(stage: Stage) -> dict:
    admin = Client(stage, ADMIN_NAME)
    clients: dict = {ADMIN_NAME: admin}
    try:
        await admin.login(stage.admin_password)
        clients = await seed_people(stage, admin)
        info = await seed_chat(stage, clients)
        info.update(await seed_operations(stage, clients))
        spread_timestamps(stage)
        mark_index_complete(stage)
        info.update(await seed_golive(stage, clients, info["streams"]))
        info.update(await seed_access_limits(stage, clients, info))
        info.update(await seed_notifications(stage, clients, info))
        info.update(seed_recordings(stage))
        return info
    finally:
        for c in clients.values():
            await c.close()


if __name__ == "__main__":
    sys.exit(main())
