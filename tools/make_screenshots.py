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

    async def api(self, method: str, path: str, body=None, ok=(200, 201)):
        r = await self.http.request(method, f"{self.stage.direct}{path}", json=body)
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
    ("casey", "I can bring the projector for the slideshow.", {"react": [(TADA, ["sam", "alex", "river"])]}),
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
    def context(self, user: str | None, viewport=None, theme: str | None = None, mobile: bool = False):
        opts = dict(viewport=viewport or VIEWPORT, ignore_https_errors=True, device_scale_factor=1,
                    extra_http_headers={"CF-Connecting-IP": ADDRESSES.get(user or "", "192.0.2.10")},
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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
        return info
    finally:
        for c in clients.values():
            await c.close()


if __name__ == "__main__":
    sys.exit(main())
