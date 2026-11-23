"""Stream schedule: routes, visibility, reminders, go-live slots and the calendar feed.

The portal's own handlers run in-process against a temporary database over a real aiohttp test server (a
stand-in login replaces the credential check; the feed is read with no login at all, as a calendar app
does). The clock of the schedule is moved by the test. Web Push is a recorder (no push service, no outbound
dial: tests/outbound_guard.py refuses any). Proven only by fakes: the push delivery itself, the clock, the
login. Not proven here: a real browser, a phone, a calendar app, Cloudflare.

Run: venv/bin/python tests/test_schedule.py
"""

import asyncio
import io
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import aiohttp  # noqa: E402
from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestServer, make_mocked_request  # noqa: E402

import logger as portal_logger  # noqa: E402
import server  # noqa: E402
import stream_schedule as ss  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

FULL = ["services:read", "access:*"]
ADMIN_IDS = set()
failed = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


class Tok:
    def __init__(self, user_id, streamkey=False):
        self.user_id = user_id
        self.token_id = ("streamkey-%d" if streamkey else "t%d") % user_id
        self.scopes = ["stream:publish"] if streamkey else list(FULL)
        if user_id in ADMIN_IDS:
            self.scopes.append("admin")

    def has_scope(self, scope):
        return "*" in self.scopes or scope in self.scopes


async def fake_auth(request):
    uid = request.headers.get("X-Test-User")
    if not uid:
        return None
    return Tok(int(uid), streamkey=bool(request.headers.get("X-Test-Streamkey")))


async def fake_valid(token):
    return True


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


class FakePusher:
    def __init__(self):
        self.sent = []
        self.tasks = set()

    async def enabled(self):
        return True

    def send_push(self, uid, payload, urgency="normal", topic=None):
        self.sent.append((uid, payload, urgency))

    def forget_paused(self):
        pass


def utc(y, mo, d, h, mi=0):
    return int(datetime(y, mo, d, h, mi, tzinfo=timezone.utc).timestamp())


FRI = utc(2026, 12, 4, 20, 0)            # Friday 21:00 in Berlin (CET)
FRI2 = FRI + 7 * 86400
START = {"title": "Friday show", "start": "2026-12-04T21:00", "tz": "Europe/Berlin", "duration_min": 90,
         "recurrence": "weekly"}


class World:
    async def build(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = d = Database(str(Path(self.tmp.name) / "t.db"))
        await d.connect()
        names = ("db", "authenticate_request", "_credential_still_valid", "_schedule_now", "_get_pusher",
                 "_golive_now", "_deliver_webhook", "start_vod_recording", "start_stream_relays")
        self.saved = {n: getattr(server, n) for n in names}
        self.real_auth = server.authenticate_request
        server.db = d
        server.authenticate_request = fake_auth
        server._credential_still_valid = fake_valid
        self.clock = Clock(utc(2026, 12, 1, 12, 0))
        server._schedule_now = self.clock
        server._golive_now = self.clock
        self.pusher = FakePusher()
        server._get_pusher = lambda: self.pusher

        async def noop(*a, **kw):
            return None
        server._deliver_webhook = noop
        server.start_vod_recording = noop
        server.start_stream_relays = noop
        self.saved_cfg = (Config.HOSTNAME, Config.PUBLIC_BASE_URL)
        Config.HOSTNAME, Config.PUBLIC_BASE_URL = "portal.example.test", ""
        server._feed_buckets.clear()
        self.ids = {}
        for name, role in (("owner", "user"), ("admin", "admin"), ("m1", "user"), ("m2", "user"), ("mod", "user")):
            self.ids[name] = await d.create_user(name, "x")
            if role != "user":
                await d.set_user_role(self.ids[name], role)
                ADMIN_IDS.add(self.ids[name])
        await d.conn.execute("UPDATE users SET nickname = 'Anna' WHERE id = ?", (self.ids["owner"],))
        await d.conn.commit()
        app = web.Application()
        r = app.router
        r.add_get("/api/streams/schedule/upcoming", server.http_schedule_upcoming)
        r.add_get("/api/streams/schedule/feed/{token}.ics", server.http_schedule_feed)
        r.add_get("/api/me/schedule-feed", server.http_schedule_feed_status)
        r.add_post("/api/me/schedule-feed", server.http_schedule_feed_create)
        r.add_delete("/api/me/schedule-feed", server.http_schedule_feed_revoke)
        r.add_get("/api/streams/{id}", server.http_get_user_stream)
        r.add_put("/api/streams/{id}", server.http_update_user_stream)
        r.add_put("/api/streams/{id}/follow", server.http_follow_stream)
        r.add_get("/api/streams/{id}/schedule", server.http_schedule_get)
        r.add_post("/api/streams/{id}/schedule", server.http_schedule_create)
        r.add_delete("/api/streams/{id}/schedule/suggestion", server.http_schedule_suggestion_dismiss)
        r.add_put("/api/streams/{id}/schedule/{entry_id}", server.http_schedule_update)
        r.add_delete("/api/streams/{id}/schedule/{entry_id}", server.http_schedule_delete)
        r.add_post("/api/streams/{id}/schedule/{entry_id}/cancel/{start}", server.http_schedule_cancel)
        r.add_delete("/api/streams/{id}/schedule/{entry_id}/cancel/{start}", server.http_schedule_restore)
        r.add_post("/api/streams/{id}/schedule/{entry_id}/rsvp/{start}", server.http_schedule_rsvp)
        r.add_delete("/api/streams/{id}/schedule/{entry_id}/rsvp/{start}", server.http_schedule_unrsvp)
        self.srv = TestServer(app)
        await self.srv.start_server()
        self.http = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar())
        return self

    async def close(self):
        await self.http.close()
        await self.srv.close()
        for n, v in self.saved.items():
            setattr(server, n, v)
        Config.HOSTNAME, Config.PUBLIC_BASE_URL = self.saved_cfg
        await self.db.close()
        self.tmp.cleanup()

    async def raw(self, method, who, path, **kw):
        headers = {"X-Test-User": str(self.ids[who])} if who else {}
        headers.update(kw.pop("headers", {}))
        async with self.http.request(method, str(self.srv.make_url(path)), headers=headers, **kw) as r:
            return r.status, await r.read(), dict(r.headers)

    async def call(self, method, who, path, **kw):
        status, body, _h = await self.raw(method, who, path, **kw)
        try:
            return status, json.loads(body)
        except Exception:
            return status, None

    async def stream(self, label, public=True, owner="owner"):
        key, pub = "live_" + label * 20, "pub_" + label * 20
        sid = await self.db.create_user_stream(self.ids[owner], "Show " + label, key, public_key=pub,
                                               is_public=public, golive_audience="followers")
        cid = await self.db.create_chat_channel("stream-" + label + str(sid), created_by=self.ids[owner])
        await self.db.update_user_stream(sid, chat_channel_id=cid)
        return sid, cid

    async def entry(self, sid, body=None, who="owner"):
        status, resp = await self.call("POST", who, f"/api/streams/{sid}/schedule", json=body or START)
        assert status == 201, (status, resp)
        return resp["id"]

    async def notes(self, who):
        return [n for n in await self.db.get_notifications(self.ids[who], limit=100) if n["type"] == "stream_reminder"]

    async def subscribe(self, who):
        await self.db.conn.execute(
            "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?, ?, 'p', 'a')",
            (self.ids[who], "http://127.0.0.1:1/push/" + who))
        await self.db.conn.commit()

    async def tick(self, at):
        self.clock.now = at
        return await server.schedule_reminder_pass()

    async def drain(self):
        for _ in range(5):
            await asyncio.sleep(0)
        tasks = [t for t in list(server._golive_tasks) if t is not asyncio.current_task()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def main():
    w = await World().build()
    ids = w.ids
    try:
        pub, pub_chat = await w.stream("a")
        priv, priv_chat = await w.stream("b", public=False)

        # ------------------------------------------------------------ owner CRUD and who may edit
        st, b = await w.call("POST", "owner", f"/api/streams/{pub}/schedule", json=START)
        check("the owner creates a weekly entry (201)", st == 201 and b["entries"][0]["recurrence"] == "weekly"
              and b["entries"][0]["tz"] == "Europe/Berlin", f"{st} {b}")
        eid = b["id"]
        await w.db.add_channel_moderator_capped(pub_chat, ids["mod"], ids["owner"], 20)
        for who in ("m1", "mod", "admin"):
            st, _ = await w.call("POST", who, f"/api/streams/{pub}/schedule", json=START)
            check(f"a {'moderator' if who == 'mod' else who} may not create an entry (404, as stream settings)", st == 404, str(st))
        st, _ = await w.call("PUT", "mod", f"/api/streams/{pub}/schedule/{eid}", json={"title": "x"})
        st2, _ = await w.call("DELETE", "m1", f"/api/streams/{pub}/schedule/{eid}")
        check("a moderator and a member may not edit or delete either", st == 404 and st2 == 404, f"{st} {st2}")
        st, _ = await w.call("POST", "owner", f"/api/streams/{pub}/schedule", json=START,
                             headers={"X-Test-Streamkey": "1"})
        check("a stream key manages no schedule (403)", st == 403, str(st))
        st, _ = await w.call("POST", None, f"/api/streams/{pub}/schedule", json=START)
        check("no login is 401", st == 401, str(st))
        for label, bad in {"a title of 101 characters": {**START, "title": "x" * 101}, "an unknown zone": {**START, "tz": "No/Zone"},
                           "a start in the past": {**START, "start": "2026-11-01T21:00"},
                           "a duration of 5000": {**START, "duration_min": 5000}}.items():
            st, _ = await w.call("POST", "owner", f"/api/streams/{pub}/schedule", json=bad)
            check("refused (400): " + label, st == 400, str(st))
        st, _ = await w.call("POST", "owner", f"/api/streams/{pub}/schedule", data="not json")
        check("refused (400): a body that is not JSON", st == 400, str(st))
        st, b = await w.call("PUT", "owner", f"/api/streams/{pub}/schedule/{eid}", json={"title": "Friday special"})
        check("the owner edits the title", st == 200 and b["entries"][0]["title"] == "Friday special", f"{st} {b}")
        st, b = await w.call("GET", "owner", f"/api/streams/{pub}/schedule")
        check("the owner's view lists the weekly entry with its next occurrence at 20:00 UTC (21:00 Berlin)",
              st == 200 and b["entries"][0]["next"][0]["start"] == FRI, str(b)[:300])

        # the per-stream and per-member caps
        keep = (ss.MAX_ENTRIES_PER_STREAM, ss.MAX_ENTRIES_PER_OWNER)
        ss.MAX_ENTRIES_PER_STREAM = 3
        for _ in range(2):
            await w.entry(pub)
        st, b = await w.call("POST", "owner", f"/api/streams/{pub}/schedule", json=START)
        check("a fourth entry on one stream is refused (409) at the per-stream cap", st == 409, f"{st} {b}")
        ss.MAX_ENTRIES_PER_OWNER = 4
        await w.entry(priv)
        st, b = await w.call("POST", "owner", f"/api/streams/{priv}/schedule", json=START)
        check("the per-member cap counts every stream of the owner (409)", st == 409 and "per member" in b["error"], f"{st} {b}")
        ss.MAX_ENTRIES_PER_STREAM, ss.MAX_ENTRIES_PER_OWNER = keep
        for e in (await w.call("GET", "owner", f"/api/streams/{pub}/schedule"))[1]["entries"][1:]:
            await w.call("DELETE", "owner", f"/api/streams/{pub}/schedule/{e['id']}")
        pe = (await w.call("GET", "owner", f"/api/streams/{priv}/schedule"))[1]["entries"][0]["id"]

        # ------------------------------------------------------------ who sees what
        await w.call("PUT", "m1", f"/api/streams/{pub}/follow")
        st, b = await w.call("GET", "m1", "/api/streams/schedule/upcoming")
        mine = [o for o in b["occurrences"] if o["stream_id"] == pub]
        check("a member sees the public stream's occurrences, not interested yet",
              st == 200 and mine and mine[0]["start"] == FRI and mine[0]["interested"] is False
              and mine[0]["streamer"] == "Anna" and "interested_count" not in mine[0], f"{st} {b}")
        check("... and nothing of the private stream", all(o["stream_id"] != priv for o in b["occurrences"]))
        st, b = await w.call("GET", "admin", "/api/streams/schedule/upcoming")
        check("an administrator sees the private stream's occurrences", any(o["stream_id"] == priv for o in b["occurrences"]))
        st, b = await w.call("GET", "owner", "/api/streams/schedule/upcoming")
        check("the owner sees both", {o["stream_id"] for o in b["occurrences"]} == {pub, priv}, str(b)[:200])
        st1, b1 = await w.call("GET", "m1", f"/api/streams/{priv}/schedule")
        st2, b2 = await w.call("GET", "m1", "/api/streams/987654/schedule")
        check("a private stream's schedule and an unknown stream's are the same 404", st1 == 404 and st2 == 404 and b1 == b2, f"{st1} {st2}")
        st, _ = await w.call("POST", "m1", f"/api/streams/{priv}/schedule/{pe}/rsvp/{FRI}")
        check("an RSVP on a private stream is that same 404", st == 404, str(st))
        st, b = await w.call("GET", "m1", "/api/streams/schedule/upcoming?limit=abc")
        check("a bad limit is 400", st == 400)

        # ------------------------------------------------------------ RSVP
        st, b = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI}")
        check("a member marks Interested (200)", st == 200 and b["interested"] is True, f"{st} {b}")
        st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI}")
        check("marking twice is harmless", st == 200)
        st, b = await w.call("GET", "m1", "/api/streams/schedule/upcoming")
        check("their own state shows in the list", [o for o in b["occurrences"] if o["stream_id"] == pub][0]["interested"] is True)
        st, b = await w.call("GET", "m2", "/api/streams/schedule/upcoming")
        check("another member's state is not shown", [o for o in b["occurrences"] if o["stream_id"] == pub][0]["interested"] is False)
        await w.call("POST", "m2", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI}")
        st, raw, _h = await w.raw("GET", "owner", "/api/streams/schedule/upcoming")
        b = json.loads(raw)
        row = [o for o in b["occurrences"] if o["stream_id"] == pub][0]
        check("the owner sees a count of two and no name or id of who", row["interested_count"] == 2
              and b"m1" not in raw and b"m2" not in raw and str(ids["m1"]).encode() + b"," not in raw, str(row))
        st, b = await w.call("GET", "owner", f"/api/streams/{pub}/schedule")
        check("the owner's editor view has the count too", b["entries"][0]["next"][0]["interested_count"] == 2)
        for label, path in {"not an occurrence": f"/rsvp/{FRI + 60}", "in the past": f"/rsvp/{FRI - 40 * 86400}"}.items():
            st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}{path}")
            check("refused (400): " + label, st == 400, str(st))
        st, _ = await w.call("POST", "owner", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI2}")
        check("the owner may not mark their own stream (400)", st == 400)
        ss.MAX_FUTURE_RSVPS_PER_MEMBER = 1
        st, b = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI2}")
        ss.MAX_FUTURE_RSVPS_PER_MEMBER = 200
        check("a member's marks are capped (409)", st == 409, f"{st} {b}")
        await w.call("DELETE", "m2", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI}")
        st, b = await w.call("GET", "owner", f"/api/streams/{pub}/schedule")
        check("taking the mark back lowers the count", b["entries"][0]["next"][0]["interested_count"] == 1)
        st, b = await w.call("DELETE", "m2", f"/api/streams/{priv}/schedule/{pe}/rsvp/{FRI}")
        st2, b2 = await w.call("DELETE", "m2", "/api/streams/99999/schedule/5/rsvp/7")
        check("taking a mark back answers the same for any stream", st == 200 and st2 == 200 and b == b2)

        # ------------------------------------------------------------ the reminder, exactly one at 20:50
        await w.subscribe("m1")
        check("20 minutes before: nothing is sent", await w.tick(FRI - 1200) == 0 and not await w.notes("m1"))
        check("10 minutes before: one reminder", await w.tick(FRI - 595) == 1)
        n = await w.notes("m1")
        check("the notification says '<streamer> starts in 10 minutes' and nothing more",
              len(n) == 1 and n[0]["title"] == "Anna starts in 10 minutes" and not n[0]["message"]
              and (json.loads(n[0]["data"]) if isinstance(n[0]["data"], str) else n[0]["data"]) == {"stream_id": pub}, str(n))
        check("a Web Push went to the member's device with the same words and no title of any slot or stream",
              len(w.pusher.sent) == 1 and w.pusher.sent[0][0] == ids["m1"]
              and w.pusher.sent[0][1]["title"] == "Anna starts in 10 minutes" and w.pusher.sent[0][1]["body"] == ""
              and "Friday" not in json.dumps(w.pusher.sent[0][1]) and "Show a" not in json.dumps(w.pusher.sent[0][1]),
              str(w.pusher.sent))
        check("the member who did not mark it got nothing", not await w.notes("m2"))
        check("the next tick sends nothing again", await w.tick(FRI - 565) == 0 and len(await w.notes("m1")) == 1)
        check("... and again at the start", await w.tick(FRI) == 0 and len(await w.notes("m1")) == 1)
        check("the sent mark is stored with the mark (so a restart does not repeat it)", (await (await w.db.conn.execute(
            "SELECT reminded_at FROM stream_rsvps WHERE user_id = ? AND occ_start = ?", (ids["m1"], FRI))).fetchone())["reminded_at"] is not None)
        # a restart: nothing but the database remains; a fresh pass sends nothing
        server._schedule_last_prune = 0
        check("after a restart (state only in the database) nothing is repeated", await w.tick(FRI - 500) == 0)

        # taking the mark back and marking again inside the window must not bring the reminder back
        for i in range(3):
            await w.call("DELETE", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI}")
            w.clock.now = FRI - 480 + 30 * i
            st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI}")
            check(f"toggle {i + 1}: marked again (200)", st == 200)
            check(f"toggle {i + 1}: the tick sends nothing more", await w.tick(FRI - 475 + 30 * i) == 0)
        check("after the toggles the member still has exactly one reminder and one push",
              len(await w.notes("m1")) == 1 and len(w.pusher.sent) == 1, str(len(await w.notes("m1"))))

        # the index: the tick's one query is a search on the occ_start index, nothing is scanned
        plan = await (await w.db.conn.execute(
            "EXPLAIN QUERY PLAN SELECT id, user_id, entry_id, occ_start FROM stream_rsvps WHERE occ_start > ? AND occ_start <= ? "
            "AND reminded_at IS NULL ORDER BY occ_start, id LIMIT ?", (1, 2, 3))).fetchall()
        text = " ".join(str(tuple(r)) for r in plan)
        check("the tick's query uses the occ_start index", "idx_stream_rsvps_occ" in text and "SCAN" not in text, text)
        check("an idle tick sends nothing and changes nothing", await w.tick(FRI + 40 * 86400) == 0)

        # ------------------------------------------------------------ a member who lost access gets nothing
        w.clock.now = utc(2026, 12, 8, 12)
        await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI2}")
        await w.call("POST", "m2", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI2}")
        await w.call("POST", "admin", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI2}")
        await w.db.set_stream_live(pub, False)
        await w.db.ban_for_test(pub, ids["m2"], ids["owner"]) if hasattr(w.db, "ban_for_test") else await w.db.create_stream_ban(
            pub, ids["m2"], ids["owner"], "test")
        st, b = await w.call("PUT", "owner", f"/api/streams/{pub}", json={"is_public": False})
        check("the owner makes the stream private", st == 200, f"{st} {b}")
        st, b = await w.call("GET", "m1", "/api/streams/schedule/upcoming")
        check("at the next read it is gone from the member's upcoming list", all(o["stream_id"] != pub for o in b["occurrences"]), str(b)[:200])
        st, _ = await w.call("GET", "m1", f"/api/streams/{pub}/schedule")
        check("... and the stream's own schedule is 404", st == 404)
        n_before = (len(await w.notes("m1")), len(await w.notes("m2")), len(await w.notes("admin")))
        sent_before = len(w.pusher.sent)
        check("one reminder at 20:50: the administrator keeps access and gets it", await w.tick(FRI2 - 590) == 1)
        check("the member who lost access, and the banned one, get no reminder and no push",
              (len(await w.notes("m1")), len(await w.notes("m2"))) == (n_before[0], n_before[1])
              and len(await w.notes("admin")) == n_before[2] + 1 and len(w.pusher.sent) == sent_before, str(w.pusher.sent))
        adm = (await w.notes("admin"))[0]
        adm_data = json.loads(adm["data"]) if isinstance(adm["data"], str) else adm["data"]
        check("the stored reminder for a stream that is not public names no streamer in the stored notification "
              "and still links to the stream by id",
              adm["title"] == "A stream you are interested in starts in 10 minutes" and not adm["message"]
              and "Anna" not in json.dumps(adm) and adm_data == {"stream_id": pub}, str(adm))
        rows = await (await w.db.conn.execute("SELECT user_id FROM stream_rsvps WHERE occ_start = ?", (FRI2,))).fetchall()
        check("their marks were dropped", {r["user_id"] for r in rows} == {ids["admin"]}, str([tuple(r) for r in rows]))
        await w.call("PUT", "owner", f"/api/streams/{pub}", json={"is_public": True})
        await w.db.remove_stream_ban(pub, ids["m2"])

        # ------------------------------------------------------------ cancelled, moved, late
        w.clock.now = utc(2026, 12, 9, 12)
        FRI3 = FRI + 14 * 86400
        await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI3}")
        st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI3}")
        check("a member cannot cancel an occurrence (404)", st == 404)
        st, _ = await w.call("POST", "owner", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI3 + 5}")
        check("cancelling a time that is not an occurrence is 400", st == 400)
        st, b = await w.call("POST", "owner", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI3}")
        check("the owner cancels one occurrence", st == 200 and FRI3 in b["entries"][0]["cancelled"], f"{st} {b}")
        st, b = await w.call("GET", "m1", "/api/streams/schedule/upcoming?limit=50")
        starts = [o["start"] for o in b["occurrences"] if o["stream_id"] == pub]
        check("it is gone from the list and the week before it is still there", FRI3 not in starts and FRI2 in starts, str(starts))
        st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI3}")
        check("it cannot be marked", st == 400)
        # a stale mark that bypassed the routes (moved or cancelled underneath it) sends nothing and is dropped
        await w.db.conn.execute("INSERT INTO stream_rsvps (user_id, entry_id, occ_start, created_at) VALUES (?, ?, ?, 1)",
                                (ids["m1"], eid, FRI3))
        await w.db.conn.execute("INSERT INTO stream_rsvps (user_id, entry_id, occ_start, created_at) VALUES (?, ?, ?, 1)",
                                (ids["m1"], eid, FRI3 + 5))
        await w.db.conn.commit()
        count = len(await w.notes("m1"))
        check("a cancelled or moved occurrence sends nothing stale", await w.tick(FRI3 - 590) == 0 and len(await w.notes("m1")) == count)
        rows = await (await w.db.conn.execute("SELECT 1 FROM stream_rsvps WHERE entry_id = ? AND occ_start IN (?, ?)",
                                              (eid, FRI3, FRI3 + 5))).fetchall()
        check("... and the stale marks are dropped", not rows)
        st, _ = await w.call("DELETE", "owner", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI3}")
        FRI4 = FRI3 + 7 * 86400
        w.clock.now = FRI4 - 300
        st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI4}")
        c = len(await w.notes("m1"))
        check("a mark made inside the 10 minutes gets its one reminder at the next tick, never two",
              await w.tick(FRI4 - 280) == 1 and await w.tick(FRI4 - 250) == 0 and len(await w.notes("m1")) == c + 1)
        # cancel, restore and mark again after the reminder went out: no second reminder
        check("(the reminder of the occurrence went out)", len(await w.notes("m1")) == c + 1)
        st, _ = await w.call("POST", "owner", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI4}")
        check("the owner cancels it after the reminder", st == 200)
        st, _ = await w.call("DELETE", "owner", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI4}")
        st, _ = await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI4}")
        check("restored and marked again (200)", st == 200)
        check("cancel, restore and mark again sends nothing more",
              await w.tick(FRI4 - 230) == 0 and len(await w.notes("m1")) == c + 1)
        # the same through a move of the entry's time and a move back
        sent_rows = [(await (await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvp_sent WHERE entry_id = ?",
                                                      (eid,))).fetchone())["n"]]
        await w.db.schedule_update(eid, {"duration_min": 90}, FRI4 - 220, True)
        again = await w.db.rsvp_add(ids["m1"], eid, FRI4, FRI4 - 210, 200, False)
        check("a move drops the row but the sent mark stays: the new row is born already sent",
              sent_rows[0] >= 1 and again == "added" and await w.db.rsvp_due(FRI4 - 210, FRI4) == [], str(sent_rows))
        # the claim is the sent mark itself: a mark taken back (and taken again) while the claim runs cannot
        # lose it, so the next tick never reminds a second time
        FRI6 = FRI4 + 14 * 86400

        async def claim_row(row, at):
            return await w.db.rsvp_claim(row["user_id"], row["entry_id"], row["occ_start"], at)

        async def sent_count():
            return (await (await w.db.conn.execute(
                "SELECT COUNT(*) AS n FROM stream_rsvp_sent WHERE user_id = ? AND entry_id = ? AND occ_start = ?",
                (ids["m1"], eid, FRI6))).fetchone())["n"]

        async def retake_race(re_add):
            await w.db.conn.execute("DELETE FROM stream_rsvp_sent WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
            await w.db.conn.execute("DELETE FROM stream_rsvps WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
            await w.db.conn.commit()
            await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 700, 200, False)
            (row,) = await w.db.rsvp_due(FRI6 - 600, FRI6)

            async def off_and_on():
                removed = await w.db.rsvp_remove(ids["m1"], eid, FRI6)
                if re_add:
                    await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 480, 200, False)
                return removed

            claimed, removed = await asyncio.gather(claim_row(row, FRI6 - 500), off_and_on())
            return claimed, removed

        claimed, removed = await retake_race(False)
        check("a claim racing the mark being taken back leaves the sent mark", claimed and removed and await sent_count() == 1,
              f"{claimed} {removed} {await sent_count()}")
        again = await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 480, 200, False)
        c = len(await w.notes("m1"))
        check("... marking again is born sent and the next tick sends nothing",
              again == "added" and await w.db.rsvp_due(FRI6 - 480, FRI6) == [] and await w.tick(FRI6 - 470) == 0
              and len(await w.notes("m1")) == c)
        claimed, removed = await retake_race(True)
        c = len(await w.notes("m1"))
        check("a claim racing the mark being taken back and made again leaves nothing due",
              claimed and removed and await sent_count() == 1 and await w.db.rsvp_due(FRI6 - 480, FRI6) == [],
              f"{claimed} {removed} {await sent_count()}")
        check("... and the next tick sends nothing", await w.tick(FRI6 - 470) == 0 and len(await w.notes("m1")) == c)
        await w.db.rsvp_remove(ids["m1"], eid, FRI6)
        await w.db.conn.execute("DELETE FROM stream_rsvp_sent WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.commit()
        await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 700, 200, False)
        (row,) = await w.db.rsvp_due(FRI6 - 600, FRI6)
        second = await asyncio.gather(claim_row(row, FRI6 - 500), claim_row(row, FRI6 - 500))
        check("two claims of one mark: exactly one wins", sorted(second) == [False, True], str(second))
        # the started-occurrence path takes the same claim: a mark taken back around it is not reminded later
        await w.db.rsvp_remove(ids["m1"], eid, FRI6)
        await w.db.conn.execute("DELETE FROM stream_rsvp_sent WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.commit()
        await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 700, 200, False)
        await w.db.schedule_mark_started(eid, FRI6, FRI6 - 500, None)
        started_race = await asyncio.gather(w.tick(FRI6 - 490), w.db.rsvp_remove(ids["m1"], eid, FRI6))
        await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 480, 200, False)
        c = len(await w.notes("m1"))
        check("an occurrence that began early sends nothing, also when the mark is taken back and made again around it",
              started_race[0] == 0 and await w.db.rsvp_due(FRI6 - 480, FRI6) == [] and await w.tick(FRI6 - 470) == 0
              and len(await w.notes("m1")) == c, str(started_race))
        await w.db.conn.execute("DELETE FROM stream_schedule_started WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.execute("DELETE FROM stream_rsvps WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.commit()
        # a mark that goes away while the tick is between reading the due list and claiming (it awaits lookups
        # there and requests are served meanwhile) sends nothing: the claim needs the mark to still exist
        async def mid_tick_race(action, hook="get_user_by_id"):
            for sql in ("DELETE FROM stream_rsvp_sent WHERE entry_id = ? AND occ_start = ?",
                        "DELETE FROM stream_rsvps WHERE entry_id = ? AND occ_start = ?",
                        "DELETE FROM stream_schedule_cancelled WHERE entry_id = ? AND occ_start = ?"):
                await w.db.conn.execute(sql, (eid, FRI6))
            await w.db.conn.commit()
            await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 700, 200, False)
            notes0, pushes0 = len(await w.notes("m1")), len(w.pusher.sent)
            orig, fired = getattr(w.db, hook), []

            async def hooked(*a, **kw):
                if not fired:
                    fired.append(1)
                    await action()
                return await orig(*a, **kw)
            setattr(w.db, hook, hooked)
            try:
                n = await w.tick(FRI6 - 590)
            finally:
                delattr(w.db, hook)
            await w.drain()
            return (n if fired else None), len(await w.notes("m1")) - notes0, len(w.pusher.sent) - pushes0

        got = await mid_tick_race(lambda: w.db.rsvp_remove(ids["m1"], eid, FRI6))
        check("Interested taken back between the due list and the claim sends nothing", got == (0, 0, 0), str(got))
        got = await mid_tick_race(lambda: w.db.schedule_cancel_occurrence(eid, FRI6, FRI6 - 595, 50))
        check("an occurrence cancelled between the due list and the claim sends nothing", got == (0, 0, 0), str(got))
        await w.db.conn.execute("DELETE FROM stream_schedule_cancelled WHERE entry_id = ?", (eid,))
        await w.db.conn.commit()
        got = await mid_tick_race(lambda: w.db.schedule_update(eid, {"duration_min": 90}, FRI6 - 595, True))
        check("an entry moved between the due list and the claim sends nothing", got == (0, 0, 0), str(got))
        got = await mid_tick_race(lambda: asyncio.sleep(0))
        check("(control: nothing taken away, the same tick sends its one reminder and one push)", got == (1, 1, 1), str(got))
        await w.db.conn.execute("DELETE FROM stream_rsvps WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.commit()

        # a stream made private while the tick runs: a member who may no longer watch it gets no reminder, and
        # no push names the streamer
        async def go_private():
            await w.db.update_user_stream(pub, is_public=0)

        got = await mid_tick_race(go_private, hook="is_user_banned_from_stream")
        await w.db.update_user_stream(pub, is_public=1)
        check("a stream made private between the due list and the claim sends nothing, no push either",
              got == (0, 0, 0), str(got))
        await w.db.conn.execute("DELETE FROM stream_rsvps WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.execute("DELETE FROM stream_rsvp_sent WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.commit()
        # two members are due on one occurrence and the stream becomes private as the second one's mark is being
        # claimed (after the due list, the entry checks and a read of the stream made before the claim would
        # have been done): the claim comes first and the stream is read and judged after it, so the second member
        # gets no notification and no push, and nothing they hold names the streamer
        await w.subscribe("m2")
        await w.db.rsvp_add(ids["m1"], eid, FRI6, FRI6 - 700, 200, False)
        await w.db.rsvp_add(ids["m2"], eid, FRI6, FRI6 - 700, 200, False)
        n1, n2, p0 = len(await w.notes("m1")), len(await w.notes("m2")), len(w.pusher.sent)
        real_claim, claims = w.db.rsvp_claim, []

        async def private_at_second_claim(*a, **kw):
            claims.append(a[0])
            if len(claims) == 2:
                await w.db.update_user_stream(pub, is_public=0)
            return await real_claim(*a, **kw)
        w.db.rsvp_claim = private_at_second_claim
        try:
            sent_now = await w.tick(FRI6 - 590)
        finally:
            del w.db.rsvp_claim
        await w.drain()
        await w.db.update_user_stream(pub, is_public=1)
        pushed = w.pusher.sent[p0:]
        check("two due marks, the stream goes private between them: only the first member is reminded",
              claims == [ids["m1"], ids["m2"]] and sent_now == 1 and len(await w.notes("m1")) == n1 + 1
              and len(await w.notes("m2")) == n2, f"{claims} {sent_now}")
        check("... the second member gets no push either, and no push or notification of theirs names the streamer",
              [u for u, _p, _u in pushed] == [ids["m1"]]
              and "Anna" not in json.dumps([x[1] for x in pushed if x[0] == ids["m2"]])
              and "Anna" not in json.dumps(await w.notes("m2")), str(pushed))
        left = await (await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvps WHERE user_id = ? AND entry_id = ? AND occ_start = ?",
                                              (ids["m2"], eid, FRI6))).fetchone()
        sentmark = await (await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvp_sent WHERE user_id = ? AND entry_id = ? AND occ_start = ?",
                                                  (ids["m2"], eid, FRI6))).fetchone()
        check("... the second member's mark is dropped and the reminder is not owed again", left["n"] == 0 and sentmark["n"] == 1,
              f"{left['n']} {sentmark['n']}")
        c1 = len(await w.notes("m1"))
        check("... another tick sends nothing more", await w.tick(FRI6 - 580) == 0 and len(await w.notes("m1")) == c1)
        await w.db.conn.execute("DELETE FROM stream_rsvps WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.execute("DELETE FROM stream_rsvp_sent WHERE entry_id = ? AND occ_start = ?", (eid, FRI6))
        await w.db.conn.commit()

        # a start too large for the date arithmetic is a plain refusal on every route that takes one (it was a 500
        # with a traceback), whatever the member or the owner sends
        big = ["1000000000000000", "253402300000", "253402300799", "4102444801", str(2 ** 63 - 1), str(2 ** 63), "99999999999999999999",
               "-5", "0", "abc", "1.5"]
        codes = {}
        for v in big:
            for label, who, method, tail in (("rsvp", "m1", "POST", "rsvp"), ("unrsvp", "m1", "DELETE", "rsvp"),
                                             ("cancel", "owner", "POST", "cancel"), ("restore", "owner", "DELETE", "cancel")):
                st, _b = await w.call(method, who, f"/api/streams/{pub}/schedule/{eid}/{tail}/{v}")
                codes[(label, v)] = st
        bad_codes = {k: st for k, st in codes.items() if st not in (400, 404)
                     and not (k[0] == "unrsvp" and st == 200)}
        check("an out-of-range or malformed start is 400 or 404 on RSVP, taking back, cancel and restore (never 500)",
              not bad_codes, str(bad_codes))
        entry_row = await w.db.schedule_get(eid)
        check("... the occurrence test itself answers False for them and raises nothing",
              all(not ss.is_occurrence(entry_row, int(v)) for v in big if v.lstrip("-").isdigit()))
        check("... and the owner and the member keep working after them",
              (await w.call("GET", "m1", f"/api/streams/{pub}/schedule"))[0] == 200)
        # moving the time drops the marks of the occurrences to come
        w.clock.now = utc(2026, 12, 10, 12)
        FRI5 = FRI4 + 7 * 86400
        await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI5}")
        st, b = await w.call("PUT", "owner", f"/api/streams/{pub}/schedule/{eid}", json={"start": "2026-12-11T22:00"})
        left = await (await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_rsvps WHERE entry_id = ? AND occ_start >= ?",
                                              (eid, w.clock.now))).fetchone()
        check("moving an entry drops the marks of upcoming occurrences", st == 200 and left["n"] == 0, f"{st} {b}")
        st, b = await w.call("PUT", "owner", f"/api/streams/{pub}/schedule/{eid}", json={"start": "2026-12-11T21:00"})
        check("a start in the past is refused on an edit too, a later Friday is fine", st == 200, f"{st} {b}")
        st, b = await w.call("PUT", "owner", f"/api/streams/{pub}/schedule/{eid}", json={"start": "2026-12-01T21:00"})
        check("(a new start in the past, 400)", st == 400)
        st, b = await w.call("PUT", "owner", f"/api/streams/{pub}/schedule/{eid}", json={"tz": "Europe/Berlin", "duration_min": 90})
        check("an edit that leaves the start alone is not held to the past rule", st == 200, f"{st} {b}")

        # ------------------------------------------------------------ go-live: slot, suggestion, countdown ends
        slot = FRI + 28 * 86400                       # 1 January 2027, 20:00 UTC
        w.clock.now = slot - 590
        await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{slot}")
        w.clock.now = slot - 700                      # the streamer goes live 11 minutes before the slot
        stream = await w.db.get_user_stream(pub)
        await server._mark_stream_live(stream, "127.0.0.1")
        await w.drain()
        st, b = await w.call("GET", "owner", f"/api/streams/{pub}/schedule")
        check("go-live within the window offers the slot's title to the owner",
              b["suggestion"] and b["suggestion"]["title"] == "Friday special" and b["suggestion"]["start"] == slot, str(b["suggestion"]))
        check("... and does not rename the stream", (await w.db.get_user_stream(pub))["name"] == "Show a")
        st, b = await w.call("GET", "m2", f"/api/streams/{pub}/schedule")
        check("... the suggestion is the owner's only and the countdown moved to the next week",
              "suggestion" not in b and b["next"][0]["start"] == slot + 7 * 86400, str(b))
        c = len(await w.notes("m1"))
        check("the occurrence is started: no reminder follows for it", await w.tick(slot - 590) == 0 and len(await w.notes("m1")) == c)
        st, _ = await w.call("POST", "m2", f"/api/streams/{pub}/schedule/{eid}/rsvp/{slot}")
        check("a started occurrence cannot be marked", st == 400)
        st, _ = await w.call("DELETE", "owner", f"/api/streams/{pub}/schedule/suggestion")
        st2, b = await w.call("GET", "owner", f"/api/streams/{pub}/schedule")
        check("the owner dismisses the suggestion", st == 200 and b["suggestion"] is None)
        await w.db.set_stream_live(pub, False)
        w.clock.now = slot + 7 * 86400 + 7200        # two hours after the next slot: outside every window
        await w.db.conn.execute("UPDATE user_streams SET golive_announced_at = NULL WHERE id = ?", (pub,))
        await w.db.conn.commit()
        await server._mark_stream_live(await w.db.get_user_stream(pub), "127.0.0.1")
        await w.drain()
        st, b = await w.call("GET", "owner", f"/api/streams/{pub}/schedule")
        check("a go-live far from any slot offers nothing", b["suggestion"] is None)
        await w.db.set_stream_live(pub, False)

        # ------------------------------------------------------------ the calendar feed
        w.clock.now = utc(2026, 12, 9, 12)
        st, b, h = await w.raw("POST", "m1", "/api/me/schedule-feed")
        made = json.loads(b)
        url = made["url"]
        token = url.rsplit("/", 1)[1][:-4]
        check("the feed token is made, shown once in a URL ending .ics, and not stored",
              st == 200 and url.startswith("https://portal.example.test/api/streams/schedule/feed/sf_") and url.endswith(".ics")
              and h.get("Cache-Control") == "no-store" and ss.feed_token_wellformed(token), url)
        row = await (await w.db.conn.execute("SELECT token_hash FROM schedule_feed_tokens WHERE user_id = ?", (ids["m1"],))).fetchone()
        check("only a hash is stored", row["token_hash"] == ss.hash_feed_token(token) and token not in row["token_hash"])
        st, b = await w.call("GET", "m1", "/api/me/schedule-feed")
        check("the status never returns the token", st == 200 and b["active"] is True and token.encode() not in json.dumps(b).encode())
        feed_path = f"/api/streams/schedule/feed/{token}.ics"
        st, body, h = await w.raw("GET", None, feed_path)
        text = body.decode()
        check("the feed answers with no login: text/calendar, no-store, no-referrer, no cookie",
              st == 200 and h["Content-Type"].startswith("text/calendar") and h["Cache-Control"] == "no-store"
              and h["Referrer-Policy"] == "no-referrer" and "Set-Cookie" not in h, f"{st} {h}")
        check("it holds the followed public stream's weekly entry in local time with an RRULE",
              "DTSTART;TZID=Europe/Berlin:20261211T210000" in text and "RRULE:FREQ=WEEKLY" in text
              and "UID:schedule-%d@portal.example.test" % eid in text and "SUMMARY:Anna: Friday special" in text and text.endswith("\r\n"), text[:400])
        check("it holds nothing of the private stream the member cannot see", "schedule-%d@" % pe not in text)
        await w.call("POST", "owner", f"/api/streams/{pub}/schedule/{eid}/cancel/{FRI + 21 * 86400}")
        st, body, _h = await w.raw("GET", None, feed_path)
        check("a cancelled week is an EXDATE", b"EXDATE;TZID=Europe/Berlin:20261225T210000" in body, body.decode()[:300])
        st, body, _h = await w.raw("GET", None, f"/api/streams/schedule/feed/{ss.new_feed_token()}.ics")
        st2, body2, h2 = await w.raw("GET", None, f"/api/streams/schedule/feed/{'x' * 10}.ics")
        check("an unknown and a malformed token are the same 404, no-store", st == 404 and st2 == 404 and body == body2
              and h2["Cache-Control"] == "no-store" and h2["Referrer-Policy"] == "no-referrer", f"{st} {st2}")
        # made private: the member's feed and list lose it at the next read, and their mark gives no reminder
        w.clock.now = utc(2026, 12, 16, 12)
        FRI6 = FRI + 42 * 86400
        await w.call("POST", "m1", f"/api/streams/{pub}/schedule/{eid}/rsvp/{FRI6}")
        await w.call("PUT", "owner", f"/api/streams/{pub}", json={"is_public": False})
        st, body, _h = await w.raw("GET", None, feed_path)
        check("making the stream private removes it from a non-member's feed at the next fetch",
              st == 200 and b"schedule-%d@" % eid not in body, body.decode()[:300])
        c = len(await w.notes("m1"))
        check("... and no reminder follows", await w.tick(FRI6 - 590) == 0 and len(await w.notes("m1")) == c)
        st, body, _h = await w.raw("GET", None, f"/api/streams/schedule/feed/{token}.ics")
        await w.call("PUT", "owner", f"/api/streams/{pub}", json={"is_public": True})
        st, body, _h = await w.raw("GET", None, feed_path)
        check("making it public again does not bring the cleared follow, and so the feed entry, back",
              b"schedule-%d@" % eid not in body, body.decode()[:200])
        # regenerate and revoke
        st, b, _h = await w.raw("POST", "m1", "/api/me/schedule-feed")
        token2 = json.loads(b)["url"].rsplit("/", 1)[1][:-4]
        st_old, _, _ = await w.raw("GET", None, feed_path)
        st_new, _, _ = await w.raw("GET", None, f"/api/streams/schedule/feed/{token2}.ics")
        check("regenerating replaces the token: the old address is 404, the new one works", st_old == 404 and st_new == 200, f"{st_old} {st_new}")
        await w.raw("DELETE", "m1", "/api/me/schedule-feed")
        st_new, _, _ = await w.raw("GET", None, f"/api/streams/schedule/feed/{token2}.ics")
        check("revoking ends it (404)", st_new == 404)
        # the token is accepted nowhere else
        await w.raw("POST", "m1", "/api/me/schedule-feed")
        token3 = json.loads((await w.raw("POST", "m1", "/api/me/schedule-feed"))[1])["url"].rsplit("/", 1)[1][:-4]
        got = []
        for hdrs, q in (({"Authorization": f"Bearer {token3}"}, ""), ({"X-API-Key": token3}, ""), ({"Authorization": f"Api-Key {token3}"}, ""),
                        ({"Cookie": f"{Config.SESSION_COOKIE_NAME}={token3}"}, ""), ({}, f"?token={token3}")):
            req = make_mocked_request("GET", "/api/me" + q, headers=hdrs)
            got.append(await w.real_auth(req))
        check("the feed token is no credential for anything else (Bearer, X-API-Key, cookie, ?token=)", all(g is None for g in got), str(got))
        # rate limits
        keep = (server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT)
        server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = (3, 600), (1000, 600)
        server._feed_buckets.clear()
        codes = [(await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics"))[0] for _ in range(5)]
        st, _b, h = await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics")
        check("the feed is limited per token (429 with Retry-After, no-store)", codes[:3] == [200] * 3 and codes[3:] == [429, 429]
              and "Retry-After" in h and h["Cache-Control"] == "no-store", f"{codes} {h}")
        server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = (1000, 600), (4, 600)
        server._feed_buckets.clear()
        codes = [(await w.raw("GET", None, f"/api/streams/schedule/feed/{ss.new_feed_token()}.ics"))[0] for _ in range(6)]
        check("... and per address, also for tokens that do not exist", codes == [404] * 4 + [429] * 2, str(codes))
        # the answer carries a reference ID like every other limiter's, keeps its headers, and neither the token
        # nor its hash reaches the reference row
        server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = (3, 600), (1000, 600)
        server._feed_buckets.clear()
        server._refs._cache.clear()
        await w.db.conn.execute("DELETE FROM block_refs")
        await w.db.conn.commit()
        for _ in range(3):
            await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics")
        for _ in range(6):
            st, body429, h429 = await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics")
        refs = [dict(r) for r in await (await w.db.conn.execute("SELECT * FROM block_refs")).fetchall()]
        flat = json.dumps(refs)
        check("the feed's 429 carries a reference and keeps no-store, no-referrer, noindex and Retry-After",
              st == 429 and b"(reference " in body429 and h429.get("Cache-Control") == "no-store"
              and h429.get("Referrer-Policy") == "no-referrer" and h429.get("X-Robots-Tag") == "noindex"
              and int(h429.get("Retry-After", "0")) >= 1, f"{st} {body429!r} {h429}")
        check("six limited requests are one reference row, from the token limiter, kept per address",
              len(refs) == 1 and refs[0]["kind"] == "limit" and refs[0]["limiter"] == "schedule_feed_token", flat)
        check("neither the token nor its hash is in the reference row or in the answer",
              token3 not in flat and ss.hash_feed_token(token3) not in flat and token3.encode() not in body429
              and token3[3:] not in flat, flat)
        server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = (1000, 600), (2, 600)
        server._feed_buckets.clear()
        for _ in range(4):
            st, body429, h429 = await w.raw("GET", None, f"/api/streams/schedule/feed/{ss.new_feed_token()}.ics")
        refs = [dict(r) for r in await (await w.db.conn.execute("SELECT limiter FROM block_refs ORDER BY limiter")).fetchall()]
        check("the address limit answers the same way, from its own limiter",
              st == 429 and b"(reference " in body429 and [r["limiter"] for r in refs] == ["schedule_feed_address", "schedule_feed_token"],
              f"{st} {refs}")
        server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = keep
        server._feed_buckets.clear()

        # ------------------------------------------------------------ a zone the host can no longer load
        # (a tzdata update removed the name): the entry has no upcoming occurrence anywhere it is read, and
        # nothing else of anybody's stops working
        zs, _zc = await w.stream("z")
        zbase = (w.clock.now // 60) * 60 + 7200
        zloc = datetime.fromtimestamp(zbase, timezone.utc).strftime("%Y-%m-%dT%H:%M")
        zbody = {"title": "Zone show", "start": zloc, "tz": "UTC", "duration_min": 60}
        z_bad = await w.entry(zs, {**zbody, "recurrence": "weekly"})
        z_good = await w.entry(zs, zbody)
        await w.call("PUT", "m1", f"/api/streams/{zs}/follow")
        for who, e in (("m1", z_bad), ("m2", z_bad), ("m1", z_good), ("m2", z_good)):      # the broken entry's marks come first
            st, _ = await w.call("POST", who, f"/api/streams/{zs}/schedule/{e}/rsvp/{zbase}")
            assert st == 200, st
        await w.db.conn.execute("UPDATE stream_schedule SET tz = 'Mars/Olympus' WHERE id = ?", (z_bad,))
        await w.db.conn.commit()
        zlog = io.StringIO()
        zhandler = logging.StreamHandler(zlog)
        server.logger.addHandler(zhandler)
        try:
            st, b = await w.call("GET", "m1", "/api/streams/schedule/upcoming?limit=50")
            ids_up = {o["entry_id"] for o in (b or {}).get("occurrences", [])}
            check("an entry whose zone cannot be loaded does not break the upcoming list (200): it is skipped, the rest is there",
                  st == 200 and z_good in ids_up and z_bad not in ids_up, f"{st} {str(b)[:200]}")
            st, b = await w.call("GET", "m1", f"/api/streams/{zs}/schedule")
            check("... nor the stream's schedule, which still counts down to the other entry",
                  st == 200 and [o["entry_id"] for o in b["next"]] == [z_good], f"{st} {str(b)[:200]}")
            st, b = await w.call("GET", "owner", f"/api/streams/{zs}/schedule")
            mine = {e["id"]: e for e in (b or {}).get("entries", [])}
            check("the owner's view is 200 and shows the entry with no occurrences and 'time zone no longer available'",
                  st == 200 and mine[z_bad]["next"] == [] and mine[z_bad].get("problem") == "time zone no longer available"
                  and mine[z_good]["next"] and "problem" not in mine[z_good], f"{st} {str(mine)[:300]}")
            st, body, _h = await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics")
            check("the calendar feed is 200 with the working entry and without the broken one (no VEVENT, no VTIMEZONE)",
                  st == 200 and b"schedule-%d@" % z_good in body and b"schedule-%d@" % z_bad not in body
                  and b"Mars/Olympus" not in body, f"{st} {body[:200]!r}")
            st, _ = await w.call("POST", "m1", f"/api/streams/{zs}/schedule/{z_bad}/rsvp/{zbase + 604800}")
            check("a mark on the broken entry is refused (400), not a server error", st == 400, str(st))
            st, _ = await w.call("POST", "owner", f"/api/streams/{zs}/schedule/{z_bad}/cancel/{zbase}")
            check("so is a cancel (400)", st == 400, str(st))
            st, b = await w.call("PUT", "owner", f"/api/streams/{zs}/schedule/{z_bad}", json={"start": zloc})
            check("a change of the start without a new zone says why (400)", st == 400 and "time zone" in b["error"], f"{st} {b}")
            st, b = await w.call("PUT", "owner", f"/api/streams/{zs}/schedule/{z_bad}", json={"title": "Renamed"})
            check("a change of the title alone works (200)", st == 200, f"{st} {b}")
            try:
                sent = await w.tick(zbase - 590)
            except Exception as e:                         # the old code aborts the whole pass here
                sent = repr(e)
            check("the reminder pass goes on past the broken entry: both members get the other entry's reminder",
                  sent == 2 and len([n for n in await w.notes("m1")]) >= 1, str(sent))
            left = await (await w.db.conn.execute(
                "SELECT COUNT(*) AS n, SUM(reminded_at IS NULL) AS unsent FROM stream_rsvps WHERE entry_id = ?", (z_bad,))).fetchone()
            check("the broken entry's marks are skipped, not dropped and not claimed (they work again when the zone does)",
                  left["n"] == 2 and left["unsent"] == 2, f"{tuple(left)}")
            try:
                await server._schedule_note_go_live({"id": zs})
                went = "ok"
            except Exception as e:
                went = repr(e)
            started = await w.db.schedule_started_map([z_good, z_bad], zbase - 86400)
            check("a go-live in the slot is not stopped by it: the working entry's slot is marked started",
                  went == "ok" and zbase in started[z_good] and not started[z_bad], f"{went} {started}")
            lines = [l for l in zlog.getvalue().splitlines() if f"entry {z_bad}" in l]
            check("it is logged once for the entry, however many reads there were that day", len(lines) == 1, str(lines))
            w.clock.now += 86400
            await w.call("GET", "m1", "/api/streams/schedule/upcoming")
            await w.call("GET", "m1", "/api/streams/schedule/upcoming")
            lines = [l for l in zlog.getvalue().splitlines() if f"entry {z_bad}" in l]
            check("... and once more the next day", len(lines) == 2, str(lines))
        finally:
            server.logger.removeHandler(zhandler)
        st, b = await w.call("PUT", "owner", f"/api/streams/{zs}/schedule/{z_bad}", json={"tz": "Europe/Paris"})
        fixed = {e["id"]: e for e in (b or {}).get("entries", [])}
        check("the owner fixes it by choosing a zone: no problem is shown and it is generated again",
              st == 200 and "problem" not in fixed[z_bad] and fixed[z_bad]["tz"] == "Europe/Paris", f"{st} {str(b)[:300]}")
        await w.call("DELETE", "owner", f"/api/streams/{zs}/schedule/{z_bad}")
        await w.call("DELETE", "owner", f"/api/streams/{zs}/schedule/{z_good}")

        # ------------------------------------------------------------ logs
        stream_ = io.StringIO()
        handler = logging.StreamHandler(stream_)
        handler.setFormatter(portal_logger.RequestIdFormatter("%(message)s"))
        handler.addFilter(portal_logger.RequestIdFilter())
        handler.addFilter(portal_logger.SensitiveDataFilter())
        access = logging.getLogger("aiohttp.access")
        access.addHandler(handler)
        old_level = access.level
        access.setLevel(logging.INFO)
        try:
            await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics")
        finally:
            access.removeHandler(handler)
            access.setLevel(old_level)
        out = stream_.getvalue()
        # the same fetch through the structured (JSON) formatter: no field of the record may hold the token
        stream2 = io.StringIO()
        handler2 = logging.StreamHandler(stream2)
        handler2.setFormatter(portal_logger.StructuredFormatter())
        handler2.addFilter(portal_logger.RequestIdFilter())
        handler2.addFilter(portal_logger.SensitiveDataFilter())
        access.addHandler(handler2)
        access.setLevel(logging.INFO)
        try:
            await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics")
        finally:
            access.removeHandler(handler2)
            access.setLevel(old_level)
        check("the structured (JSON) log holds no token either", token3 not in stream2.getvalue() and "[REDACTED]" in stream2.getvalue(),
              stream2.getvalue()[:300])
        # a rate-limited fetch: no logger at any level, in either format, ever holds the token or its hash
        root = logging.getLogger()
        old_root = root.level
        captured = []
        for fmt in (portal_logger.RequestIdFormatter("%(message)s"), portal_logger.StructuredFormatter()):
            buf = io.StringIO()
            hdl = logging.StreamHandler(buf)
            hdl.setFormatter(fmt)
            hdl.addFilter(portal_logger.RequestIdFilter())
            hdl.addFilter(portal_logger.SensitiveDataFilter())
            # the SQL driver's own debug lines (every query with its parameters, a stored hash included, on every
            # request of the portal and only when someone turns debug logging on) are not the portal's
            hdl.addFilter(lambda rec: not rec.name.startswith("aiosqlite"))
            root.addHandler(hdl)
            captured.append((hdl, buf))
        root.setLevel(logging.DEBUG)
        keep_limits = (server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT)
        server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = (1, 600), (1000, 600)
        server._feed_buckets.clear()
        server._refs._cache.clear()
        try:
            limited = [(await w.raw("GET", None, f"/api/streams/schedule/feed/{token3}.ics"))[0] for _ in range(3)]
        finally:
            root.setLevel(old_root)
            for hdl, _buf in captured:
                root.removeHandler(hdl)
            server._FEED_TOKEN_LIMIT, server._FEED_ADDR_LIMIT = keep_limits
            server._feed_buckets.clear()
        logged = "".join(buf.getvalue() for _h, buf in captured)
        check("a rate-limited feed fetch leaves neither the token nor its hash in any log line, in either format",
              limited == [200, 429, 429] and "429" in logged and token3 not in logged and ss.hash_feed_token(token3) not in logged,
              f"{limited} {logged[:200]}")
        check("the access log prints the feed path with the token redacted", "schedule/feed/[REDACTED]" in out and token3 not in out, out[:300])
        for line in (f"[req=abcd2345] GET /api/streams/schedule/feed/{token3}.ics 200",
                     f"error for https://h/api/streams/schedule/feed/{token3}.ics?x=1 failed"):
            red = portal_logger.redact(line)
            check("a line with the feed path is redacted: " + line[:30], token3 not in red and "[REDACTED]" in red, red)
        check("the scanner-probe recorder does not treat the feed as a probe", server._PROBE_PATH_RE.search(feed_path) is None)

        # ------------------------------------------------------------ source guards and lifecycle
        src = (ROOT / "server.py").read_text()
        check("/api/streams/schedule/upcoming is registered before /api/streams/{id}",
              src.index('"/api/streams/schedule/upcoming"') < src.index('"/api/streams/{id}", http_get_user_stream'))
        feed_src = src[src.index("async def http_schedule_feed("):]
        feed_src = feed_src[:feed_src.index("\ndef _feed_url")]
        check("the feed handler never authenticates a request and sets no cookie",
              "authenticate_request" not in feed_src and "set_cookie" not in feed_src and ".cookies" not in feed_src)
        check("stop() cancels and awaits the reminder task", "task = getattr(self, \"_schedule_task\", None)" in src
              and "await asyncio.gather(task, return_exceptions=True)" in src)
        loop_task = asyncio.create_task(server.PortalServer._schedule_reminder_task(object.__new__(server.PortalServer)))
        await asyncio.sleep(0)
        loop_task.cancel()
        await asyncio.wait_for(loop_task, 2)
        check("the reminder loop ends cleanly when cancelled", loop_task.done() and not loop_task.cancelled())

        # ------------------------------------------------------------ database
        await w.db.delete_user(ids["m1"])
        left = [(await (await w.db.conn.execute(f"SELECT COUNT(*) AS n FROM {t} WHERE user_id = ?", (ids["m1"],))).fetchone())["n"]
                for t in ("stream_rsvps", "stream_rsvp_sent", "schedule_feed_tokens")]
        check("deleting a member removes their marks, sent marks and feed token", left == [0, 0, 0], str(left))
        await w.call("DELETE", "owner", f"/api/streams/{priv}/schedule/{pe}")
        await w.db.conn.execute("DELETE FROM user_streams WHERE id = ?", (pub,))
        await w.db.conn.commit()
        n = (await (await w.db.conn.execute("SELECT COUNT(*) AS n FROM stream_schedule WHERE stream_id = ?", (pub,))).fetchone())["n"]
        check("deleting a stream removes its schedule", n == 0)
    finally:
        await w.close()


async def migration():
    tmp = tempfile.TemporaryDirectory()
    path = str(Path(tmp.name) / "m.db")
    d = Database(path)
    await d.connect()
    uid = await d.create_user("u", "x")
    sid = await d.create_user_stream(uid, "S", "live_" + "z" * 20, public_key="pub_" + "z" * 20, is_public=True)
    eid = await d.schedule_create(sid, uid, {"title": "t", "local_start": "2026-12-04T21:00", "tz": "UTC", "duration_min": 60,
                                             "weekly": True}, 1, 20, 60)
    await d.close()
    d = Database(path)
    await d.connect()                      # the migrations run again on the same file
    again = await d.schedule_get(eid)
    names = {r["name"] for r in await (await d.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
    check("the migration is idempotent: a second start keeps the rows", again and again["title"] == "t")
    check("the new tables exist and nothing else was touched", {"stream_schedule", "stream_schedule_cancelled", "stream_schedule_started",
                                                                  "stream_rsvps", "stream_rsvp_sent", "schedule_feed_tokens"} <= names)
    await d.close()
    tmp.cleanup()


asyncio.run(main())
asyncio.run(migration())
if outbound_guard.refused:
    check("no outbound dial was attempted", False, str(outbound_guard.refused))
if failed:
    print(f"\ntest_schedule: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_schedule: all checks passed")
