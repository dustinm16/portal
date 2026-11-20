"""Go-live announcement: one per cooldown, the owner's message template, a payload with no keys.

The real MediaMTX publish hook (http_stream_auth), the stream update route and the
announcement code run in-process against a temporary database. Webhook delivery is replaced
by a recorder (the formats are rendered for real with webhook_formats), the recording and
relay starters are replaced by no-ops, and tests/outbound_guard.py refuses any dial that is
not loopback. Not proven here: real MediaMTX retry timing, a real OBS reconnect, a real
Discord or ntfy post (the stage smoke check and a run on the production host are for that).

* three publish and offline cycles inside the cooldown: one notification per viewer, one
  delivery per hook; two concurrent publishes: one announcement; after the cooldown a second;
  a fresh Database object on the same file (a restart) is still inside the cooldown; the
  chat state frame is not held back
* a stream.offline inside the cooldown is recorded and the following live is not announced
* the template: the three placeholders, '{0.__class__}' and other brace text literal, a value
  that contains a placeholder is not substituted again, control characters stripped, 200
  characters at most, a body-sized message is refused before the strip runs, empty means the
  default, only the owner can set it; the settings screen sets it as a property (a double quote
  in a message must not cut it short)
* the payload: streamer, title and a watch URL from the configured base URL (not the Host
  header), no stream key, pub_ key or RTMP address, in the generic body and every format
* audience: a public stream notifies every member but the owner, a private one only the
  administrators; a private stream's events reach no member's own hook and no non-generic
  hook, only a system generic hook

Run: venv/bin/python tests/test_golive.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import server  # noqa: E402
import webhook_formats  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402
from test_chat_access_loss import run  # noqa: E402

LIVE_KEY = "live_" + "L" * 24
PUB_KEY = "pub_" + "P" * 24
HOOK_URL = "https://93.184.216.34/hook"


class Transport:
    def get_extra_info(self, name, default=None):
        return ("127.0.0.1", 5555) if name == "peername" else default


class HookRequest:
    def __init__(self, data):
        self.transport = Transport()
        self._data = data
        self.headers = {"Host": "evil.example"}
        self.host = "evil.example"

    async def json(self):
        return self._data


class Clock:
    def __init__(self):
        self.now = 1_800_000_000

    def __call__(self):
        return self.now


class World:
    """Users (owner, admin, two members), a public and a private stream, hooks, a recorder."""

    async def build(self, env):
        d = self.db = env.db
        self.env = env
        self.ids = {}
        for name, role in (("owner", "user"), ("admin", "admin"), ("m1", "user"), ("m2", "user")):
            self.ids[name] = await d.create_user(name, "x")
            if role != "user":
                await d.set_user_role(self.ids[name], role)
        await d.conn.execute("UPDATE users SET nickname = 'The Owner' WHERE id = ?", (self.ids["owner"],))
        await d.conn.commit()
        self.sid = {}
        for label, public in (("pub", 1), ("priv", 0)):
            sk = LIVE_KEY if label == "pub" else "live_" + "Q" * 24
            pk = PUB_KEY if label == "pub" else "pub_" + "R" * 24
            self.sid[label] = await d.create_user_stream(
                self.ids["owner"], "Show " + label, sk, public_key=pk, is_public=bool(public))
        self.keys = {"pub": LIVE_KEY, "priv": "live_" + "Q" * 24}
        self.pubkeys = {"pub": PUB_KEY, "priv": "pub_" + "R" * 24}
        # a system generic hook, a member's own generic hook, a system discord hook
        self.hooks = {
            "sys": await d.create_webhook(None, "sys", "outgoing", url=HOOK_URL, events=["stream.live", "stream.offline"],
                                          kind="system", created_by=self.ids["admin"]),
            "member": await d.create_webhook(self.ids["m1"], "mine", "outgoing", url=HOOK_URL, events=["stream.live"]),
            "discord": await d.create_webhook(None, "disc", "outgoing", url="https://discord.com/api/webhooks/1/abc",
                                              events=["stream.live"], kind="system", fmt="discord",
                                              include_details=True, created_by=self.ids["admin"]),
        }
        self.clock = Clock()
        self.sent = []
        self.saved = {name: getattr(server, name) for name in
                      ("_golive_now", "_deliver_webhook", "start_vod_recording", "start_stream_relays")}
        self.saved_cfg = (Config.HOSTNAME, Config.PUBLIC_BASE_URL)
        Config.HOSTNAME, Config.PUBLIC_BASE_URL = "portal.example.test", ""
        server._golive_now = self.clock
        world = self

        async def record(webhook, event, payload, attempt=1, *, meta=None, **kw):
            world.sent.append({"hook": webhook["id"], "kind": webhook["kind"], "format": webhook["format"],
                               "event": event, "payload": payload, "meta": meta,
                               "details": webhook.get("include_details")})
            return {"sent": True, "success": True}

        async def noop(*a, **kw):
            return None

        server._deliver_webhook = record
        server.start_vod_recording = noop
        server.start_stream_relays = noop
        self.hook_name = {v["id"]: k for k, v in self.hooks.items()}
        return self

    def close(self):
        for name, value in self.saved.items():
            setattr(server, name, value)
        Config.HOSTNAME, Config.PUBLIC_BASE_URL = self.saved_cfg

    async def drain(self):
        for _ in range(5):
            await asyncio.sleep(0)
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()
                   and ("_deliver_webhook" in repr(t.get_coro()) or "fire_webhook_event" in repr(t.get_coro()))]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(0)

    async def publish(self, label="pub", key=None):
        resp = await server.http_stream_auth(HookRequest({
            "action": "publish", "path": "live/" + (key or self.keys[label]), "ip": "198.51.100.7",
            "user": "", "password": "", "query": ""}))
        await self.drain()
        return resp.status

    async def go_offline(self, label="pub"):
        """What the portal does when the publisher is gone: record it, as the grace task does."""
        await self.db.set_stream_live(self.sid[label], False)
        s = await self.db.get_user_stream(self.sid[label])
        asyncio.create_task(server.fire_webhook_event("stream.offline", {
            "stream_id": s["id"], "stream_name": s["name"], "owner_username": s["owner_username"]},
            meta={"stream_public": bool(s["is_public"])}))
        await self.drain()

    async def notes(self, user):
        return [n for n in await self.db.get_notifications(self.ids[user], limit=100) if n["type"] == "stream_live"]

    def live_events(self, hook=None):
        return [x for x in self.sent if x["event"] == "stream.live"
                and (hook is None or self.hook_name[x["hook"]] == hook)]


def with_world(fn):
    def runner():
        async def body(env):
            w = await World().build(env)
            try:
                await fn(w)
            finally:
                w.close()
        run(body)
    runner.__name__ = fn.__name__
    runner.__doc__ = fn.__doc__
    return runner


# ---------------------------------------------------------------------------
# the cooldown

@with_world
async def test_restarting_the_encoder_three_times_announces_once(w):
    for i in range(3):
        assert await w.publish() == 200
        if i < 2:
            await w.go_offline()
            w.clock.now += 60            # a minute between restarts: 4 minutes in all
    for who in ("admin", "m1", "m2"):
        assert len(await w.notes(who)) == 1, (who, await w.notes(who))
    assert await w.notes("owner") == []
    assert len(w.live_events("sys")) == 1 and len(w.live_events("member")) == 1 and len(w.live_events("discord")) == 1, w.sent
    # the offline events in between were still recorded and delivered
    assert len([x for x in w.sent if x["event"] == "stream.offline"]) == 2


@with_world
async def test_the_chat_state_frame_is_not_held_back(w):
    cid = await w.db.create_chat_channel("strm", created_by=w.ids["owner"])
    await w.db.conn.execute("UPDATE user_streams SET chat_channel_id = ? WHERE id = ?", (cid, w.sid["pub"]))
    await w.db.conn.commit()
    frames = []
    real = server.broadcast_to_channel

    async def spy(name, payload, **kw):
        frames.append(payload)

    server.broadcast_to_channel = spy
    try:
        await w.publish()
        await w.go_offline()
        w.clock.now += 30
        await w.publish()
    finally:
        server.broadcast_to_channel = real
    status = [f for f in frames if f.get("type") == "stream_status" and f.get("is_live") == 1]
    assert len(status) == 2, frames                  # viewers learn the state both times
    assert len(w.live_events("sys")) == 1            # but the announcement went out once


@with_world
async def test_a_retried_hook_and_concurrent_publishes_announce_once(w):
    results = await asyncio.gather(*[w.publish() for _ in range(5)])
    assert results == [200] * 5
    assert len(await w.notes("m1")) == 1 and len(w.live_events("sys")) == 1, w.sent
    # and the claim itself is exclusive when raced at the database
    wins = await asyncio.gather(*[w.db.claim_golive(w.sid["priv"], w.clock.now, 600) for _ in range(8)])
    assert wins.count(True) == 1, wins


@with_world
async def test_an_offline_inside_the_cooldown_does_not_open_a_new_announcement(w):
    await w.publish()
    await w.go_offline()
    assert [x["event"] for x in w.sent if x["hook"] == w.hooks["sys"]["id"]] == ["stream.live", "stream.offline"]
    w.clock.now += 599
    await w.publish()
    assert len(w.live_events("sys")) == 1


@with_world
async def test_after_the_cooldown_it_is_announced_again(w):
    await w.publish()
    await w.go_offline()
    w.clock.now += 600
    await w.publish()
    assert len(w.live_events("sys")) == 2 and len(await w.notes("m1")) == 2


@with_world
async def test_the_cooldown_survives_a_restart(w):
    await w.publish()
    await w.go_offline()
    path = w.db.db_path if hasattr(w.db, "db_path") else None
    assert path
    fresh = Database(path)           # a new process: nothing held in memory
    await fresh.connect()
    try:
        await fresh.reset_all_streams_offline()
        assert await fresh.claim_golive(w.sid["pub"], w.clock.now + 10, 600) is False
        assert await fresh.claim_golive(w.sid["pub"], w.clock.now + 601, 600) is True
    finally:
        await fresh.close()


@with_world
async def test_each_stream_has_its_own_cooldown(w):
    await w.publish("pub")
    await w.publish("priv")
    assert len(w.live_events("sys")) == 2


# ---------------------------------------------------------------------------
# the message

def test_template_placeholders_are_replaced_literally():
    r = server._render_golive_message
    assert r("{streamer} plays {title}: {url}", "Ann", "Zelda", "https://p/watch/1") == "Ann plays Zelda: https://p/watch/1"
    for text in ("{0}", "{streamer.__class__}", "{}", "%(title)s"):
        assert r(text, "Ann", "Zelda", "U") == text, text
    assert r("{0.__class__}", "Ann", "Zelda", "U") == "{0.__class__}"
    assert r("{title!r} {url:>9} {streamer.x}", "Ann", "Zelda", "U") == "{title!r} {url:>9} {streamer.x}"
    assert r("{{title}}", "A", "T", "U") == "{T}"            # braces around a placeholder stay
    assert r("{TITLE} {Title}", "A", "T", "U") == "{TITLE} {Title}"      # names are exact


def test_template_values_are_not_substituted_again():
    r = server._render_golive_message
    # a stream name or nickname that looks like a placeholder is shown as typed
    assert r("{title} {url} {streamer}", "{url}", "{streamer} {url}", "U") == "{streamer} {url} U {url}"
    assert r("{streamer}", "{0.__class__}", "T", "U") == "{0.__class__}"


def test_template_cleaning_and_default():
    r = server._render_golive_message
    assert r("a\x00b\x1b[31m{title}\x7f", "S", "T", "U") == "ab[31mT"
    assert r("line1\nline2\t{title}", "S", "T", "U") == "line1 line2 T"
    assert "‮" not in r("x‮{title}", "S", "T‮", "U")
    assert r("{title}", "S", "bad\x00name", "U") == "badname"
    assert r(None, "S", "T", "U") == "T just went live"
    assert r("   ", "S", "T", "U") == "T just went live"
    assert r("x" * 300 + "{title}", "S", "T", "U") == ("x" * 300 + "T")      # long templates pass; the render is capped
    assert len(r("{title}" * 500, "S", "T" * 100, "U")) <= server._GOLIVE_RENDER_MAX


def test_template_validation():
    v = server._validate_stream_fields
    assert v({"golive_message": "x" * 200}) == ({"golive_message": "x" * 200}, None)
    assert v({"golive_message": "x" * 201})[0] is None
    assert v({"golive_message": "\x00" * 50 + "x" * 200})[0] == {"golive_message": "x" * 200}     # counted after cleaning
    assert v({"golive_message": " Hi\n there "})[0] == {"golive_message": "Hi  there"}
    assert v({"golive_message": ""})[0] == {"golive_message": None}
    assert v({"golive_message": "  "})[0] == {"golive_message": None}
    assert v({"golive_message": None})[0] == {"golive_message": None}
    for bad in (5, ["a"], {"a": 1}, True):
        assert v({"golive_message": bad})[0] is None, bad
    assert "golive_message" in server._STREAM_CLIENT_FIELDS


def test_a_huge_message_is_refused_before_it_is_cleaned():
    """The per-character strip must never see a body-sized string (it would hold the event loop)."""
    v = server._validate_stream_fields
    real = server._strip_control_chars
    seen = []

    def spy(text):
        seen.append(len(text))
        return real(text)

    server._strip_control_chars = spy
    try:
        res, err = v({"golive_message": "x" * (5 * 1024 * 1024)})
        assert res is None and "at most 200" in err, (res, err)
        assert not seen, f"the strip ran over {seen} characters before the length check"
        res, err = v({"golive_message": "\x00" * 700 + "x" * 200})       # mostly controls, still small: cleaned, then counted
        assert res == {"golive_message": "x" * 200}, (res, err)
        assert v({"golive_message": "y" * (server._GOLIVE_MESSAGE_PRESTRIP_MAX + 1)})[0] is None
    finally:
        server._strip_control_chars = real


def test_the_settings_screen_sets_the_message_as_a_property_not_into_the_markup():
    """escapeHtml keeps double quotes, so a value=\"...\" attribute would cut a message at its first quote."""
    js = (ROOT / "static" / "js" / "streams.js").read_text(encoding="utf-8")
    line = next(l for l in js.splitlines() if 'id="stream-golive-input"' in l)
    assert "value=" not in line and "golive_message" not in line, line
    assert "getElementById('stream-golive-input').value = stream.golive_message" in js


@with_world
async def test_only_the_owner_edits_the_message_and_it_is_used(w):
    st, b = await w.env.call("PUT", w.ids["owner"], f"/api/streams/{w.sid['pub']}",
                             json={"golive_message": "{streamer} is playing {title} {url} {0.__class__}"})
    assert st == 200, b
    st, b = await w.env.call("PUT", w.ids["m1"], f"/api/streams/{w.sid['pub']}", json={"golive_message": "hijack"})
    assert st == 404, (st, b)
    st, b = await w.env.call("PUT", w.ids["owner"], f"/api/streams/{w.sid['pub']}", json={"golive_message": "x" * 201})
    assert st == 400, (st, b)
    assert (await w.db.get_user_stream(w.sid["pub"]))["golive_message"].startswith("{streamer} is playing")
    await w.publish()
    expect = "The Owner is playing Show pub https://portal.example.test/watch/%d {0.__class__}" % w.sid["pub"]
    n = (await w.notes("m1"))[0]
    assert n["message"] == expect, n
    assert w.live_events("sys")[0]["payload"]["message"] == expect
    # cleared: the default
    st, _ = await w.env.call("PUT", w.ids["owner"], f"/api/streams/{w.sid['pub']}", json={"golive_message": ""})
    assert st == 200 and (await w.db.get_user_stream(w.sid["pub"]))["golive_message"] is None


@with_world
async def test_a_template_set_on_a_stream_published_with_an_rtmp_token_is_used(w):
    """The rtmp_ branch builds its stream from the token join; the announcement reads the stream
    afresh, so the template still applies there."""
    await w.db.update_user_stream(w.sid["pub"], golive_message="Live: {title}")
    s = await w.db.get_user_stream(w.sid["pub"])
    thin = {k: s[k] for k in ("id", "user_id", "name", "is_public", "owner_username", "owner_nickname")}
    assert "golive_message" not in thin
    await server._announce_go_live(thin["id"])
    await w.drain()
    assert (await w.notes("m1"))[0]["message"] == "Live: Show pub"


# ---------------------------------------------------------------------------
# the payload

def walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from walk(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from walk(v)
    else:
        yield str(obj)


@with_world
async def test_the_payload_has_streamer_title_and_url_and_no_key(w):
    await w.publish()
    ev = w.live_events("sys")[0]["payload"]
    assert ev["streamer"] == "The Owner" and ev["title"] == "Show pub", ev
    assert ev["url"] == "https://portal.example.test/watch/%d" % w.sid["pub"], ev
    assert "public_key" not in ev and "stream_key" not in ev
    secrets = (LIVE_KEY, PUB_KEY, "live_", "pub_", "rtmp", "/live/", "1936", "1935", "evil.example")
    # the generic body and every format, with details on
    bodies = [json.dumps(ev)]
    for fmt in webhook_formats.FORMATS:
        req = webhook_formats.format_payload(fmt, "stream.live", ev, meta={"stream_public": True},
                                             include_details=True, portal_name="Portal",
                                             **({"secret": "s"} if fmt == "generic" else {}))
        bodies.append(req.body.decode() if hasattr(req, "body") else str(req))
    for n in await w.notes("m1"):
        bodies.append(json.dumps(n))
    for text in bodies:
        for s in secrets:
            assert s not in text, (s, text)
    # the notification carries the same facts
    data = (await w.notes("m1"))[0]["data"]
    data = json.loads(data) if isinstance(data, str) else data
    assert data["url"] == ev["url"] and data["streamer"] == "The Owner" and data["stream_id"] == w.sid["pub"], data


@with_world
async def test_the_watch_url_is_never_built_from_the_host_header(w):
    assert await w.publish() == 200          # the request above says Host: evil.example
    assert "evil.example" not in json.dumps(w.live_events("sys")[0]["payload"])
    Config.PUBLIC_BASE_URL = "https://stream.example.test"
    assert server._watch_url(7) == "https://stream.example.test/watch/7"
    Config.PUBLIC_BASE_URL = "https://stream.example.test:8443/"
    assert server._watch_url(7) == "https://stream.example.test:8443/watch/7"
    for bad in ("https://u:p@host/", "https://host/path", "https://host/?q=1", "ftp://host", "javascript:alert(1)",
                "https://ho st/", "https://host/#x", "//host"):
        Config.PUBLIC_BASE_URL = bad
        assert server._watch_url(7) == "", bad          # a bad setting gives no link, never a wrong one
    Config.PUBLIC_BASE_URL = ""
    Config.HOSTNAME = ""
    assert server._watch_url(7) == ""
    Config.HOSTNAME = "bad host/x"
    assert server._watch_url(7) == ""


@with_world
async def test_the_discord_format_has_the_message_only_with_details(w):
    await w.publish()
    ev = w.live_events("discord")[0]
    for details in (False, True):
        req = webhook_formats.format_payload("discord", "stream.live", ev["payload"], meta={"stream_public": True},
                                             include_details=details, portal_name="Portal")
        text = req.body.decode()
        assert ("The Owner" in text) is details and ("watch" in text) is details, (details, text)
    # an owner text cannot ping @everyone
    await w.db.update_user_stream(w.sid["pub"], golive_message="@everyone <@123> {title}")
    s = await w.db.get_user_stream(w.sid["pub"])
    p = server._golive_payload(s)
    text = webhook_formats.format_payload("discord", "stream.live", p, meta={"stream_public": True},
                                          include_details=True, portal_name="Portal").body.decode()
    assert "@everyone" not in text and "<@123>" not in text, text


# ---------------------------------------------------------------------------
# who is told

@with_world
async def test_a_public_stream_notifies_every_member_but_the_owner(w):
    await w.publish("pub")
    assert [len(await w.notes(n)) for n in ("owner", "admin", "m1", "m2")] == [0, 1, 1, 1]


@with_world
async def test_a_private_stream_notifies_only_those_who_may_watch_it(w):
    await w.publish("priv")
    assert [len(await w.notes(n)) for n in ("owner", "admin", "m1", "m2")] == [0, 1, 0, 0]
    # the answer is the viewing rule, not a separate list
    s = await w.db.get_user_stream(w.sid["priv"])
    for name in ("m1", "m2", "admin", "owner"):
        role = "admin" if name == "admin" else "user"
        allowed = server._stream_read_allowed(s, w.ids[name], role, False)
        assert allowed is (name in ("admin", "owner"))


@with_world
async def test_a_private_stream_reaches_only_a_system_generic_hook(w):
    await w.publish("priv")
    await w.go_offline("priv")
    got = {(w.hook_name[x["hook"]], x["event"]) for x in w.sent}
    assert got == {("sys", "stream.live"), ("sys", "stream.offline")}, got
    # a public stream still reaches the member's own hook and the third-party format
    w.sent.clear()
    await w.publish("pub")
    assert {w.hook_name[x["hook"]] for x in w.live_events()} == {"sys", "member", "discord"}


@with_world
async def test_a_hook_is_checked_again_before_a_retry(w):
    """The retry path re-reads the hook: a member's hook does not get a private stream's event then either."""
    meta_priv, meta_pub = {"stream_public": False}, {"stream_public": True}
    assert await server._webhook_current_for_event(w.hooks["member"]["id"], "stream.live", meta_priv) is None
    assert await server._webhook_current_for_event(w.hooks["member"]["id"], "stream.live", meta_pub)
    assert await server._webhook_current_for_event(w.hooks["sys"]["id"], "stream.live", meta_priv)
    assert await server._webhook_current_for_event(w.hooks["discord"]["id"], "stream.live", meta_priv) is None
    # other events are not touched by the rule
    assert server._stream_event_hook_allowed({"kind": "user"}, "message.created", {"channel_id": 1})


@with_world
async def test_a_failing_announcement_never_fails_the_publish(w):
    async def boom(*a, **kw):
        raise RuntimeError("db down")
    real = w.db.get_all_users
    w.db.get_all_users = boom
    try:
        assert await w.publish() == 200
    finally:
        w.db.get_all_users = real


@with_world
async def test_a_failing_claim_never_fails_the_publish_and_announces_nothing(w):
    async def boom(*a, **kw):
        raise RuntimeError("db locked")
    real = w.db.claim_golive
    w.db.claim_golive = boom
    try:
        assert await w.publish() == 200
    finally:
        w.db.claim_golive = real
    assert w.sent == [] and await w.notes("m1") == []


@with_world
async def test_a_database_made_before_the_columns_existed_is_upgraded_on_connect(w):
    """An existing database (here: one with the columns removed, as 1.15.0 left it) gets the two
    columns when the new code connects, and the claim works at once."""
    path = w.db.db_path
    await w.db.conn.execute("ALTER TABLE user_streams DROP COLUMN golive_message")
    await w.db.conn.execute("ALTER TABLE user_streams DROP COLUMN golive_announced_at")
    await w.db.conn.commit()
    old = Database(path)
    await old.connect()
    try:
        cols = {r["name"] for r in await (await old.conn.execute("PRAGMA table_info(user_streams)")).fetchall()}
        assert {"golive_message", "golive_announced_at"} <= cols, cols
        assert await old.claim_golive(w.sid["pub"], w.clock.now, 600) is True
        assert await old.claim_golive(w.sid["pub"], w.clock.now + 1, 600) is False
    finally:
        await old.close()


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                import traceback
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                traceback.print_exc()
    assert not outbound_guard.refused, outbound_guard.refused
    sys.exit(1 if failed else 0)
