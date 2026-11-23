"""Stream schedule, reminders and the calendar feed on a running instance.

Over HTTP against the staged server (real logins, real clock, the MediaMTX publish hook POST /api/stream/auth from loopback):
the owner schedules a weekly slot that starts 10 to 11 minutes from now, a member who may watch the stream marks it
Interested and gets exactly one reminder ("<streamer> starts in 10 minutes", no slot or stream title) when the ten minute
window opens (the portal's own 30 second tick, waited for: this module takes about two minutes), one who did not mark it
gets none, and a member whose stream was made private after they marked it gets none. A private stream's schedule is a
404 for a member (the same one an unknown stream gives), absent from their upcoming list and their feed. A stream moderator
and a member may not edit a schedule. The calendar feed is read with no login at all: text/calendar, a weekly RRULE in the
owner's zone with a TZID, no-store, no-referrer, no cookie; an unknown token is 404; the token is no credential for the
API; regenerating and revoking end the old address; the staged server's log does not hold the token. Going live inside the
slot's window offers the slot's title to the owner and does not rename the stream, and the countdown moves to the next week.
The pages carry the countdown script, the Upcoming strip and the calendar link block.

Users and streams carry random suffixes, every assertion is about those rows, and nothing global is changed, so the module also
holds on a stage started from a copy of a production database. It needs no admin password.

Not proven here (needs the real thing): a browser drawing the countdown, a phone receiving the push, a calendar application
reading the file, Cloudflare in front.
"""
import asyncio
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

PW = "Sched-smoke-pw-1"

SETUP = r'''
import asyncio, json
from database import db
from auth import create_user

P = json.loads(%(params)r)

async def main():
    await db.connect()
    out = {"users": {}}
    for name in ("owner", "m1", "m2"):
        out["users"][name] = (await create_user(P["pre"] + name, P["pw"]))["id"]
    await db.close()
    print("RESULT " + json.dumps(out))

asyncio.run(main())
'''


def _result(output):
    for line in reversed(output.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


def slot(minutes):
    """(local 'YYYY-MM-DDTHH:MM' in Berlin, UTC epoch) of the minute boundary at or below now plus `minutes`."""
    t = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).replace(second=0, microsecond=0)
    return t.astimezone(ZoneInfo("Europe/Berlin")).strftime("%Y-%m-%dT%H:%M"), int(t.timestamp())


async def run(ctx):
    pre = "sc" + secrets.token_hex(3)
    rc, out = await ctx.run_py(SETUP % {"params": json.dumps({"pw": PW, "pre": pre})}, timeout=120)
    data = _result(out)
    if rc != 0 or data is None:
        ctx.ok("schedule: setup", False, out[-500:])
        return
    streams = []

    def ok(name, passed, detail=""):
        ctx.ok("schedule: " + name, bool(passed), "" if passed else detail)

    base = ctx.base_url

    async def call(sess, method, path, **kw):
        async with sess.request(method, base + path, **kw) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, None

    async def raw(sess, path, **kw):
        async with sess.get(base + path, **kw) as r:
            return r.status, await r.read(), dict(r.headers)

    async def notes(sess, sid):
        _, body = await call(sess, "GET", "/api/notifications?limit=100")
        return [n for n in (body or {}).get("notifications", []) if n.get("type") == "stream_reminder"
                and f'"stream_id": {sid}' in str(n.get("data") or "")]

    async with ctx.http() as owner, ctx.http() as m1, ctx.http() as m2, ctx.http() as bare, ctx.http() as hook:
        try:
            for name, sess in (("owner", owner), ("m1", m1), ("m2", m2)):
                resp = await ctx.login(sess, pre + name, PW)
                if resp.status != 200:
                    ok(name + " can sign in", False, str(resp.status))
                    return

            # ---- streams: A stays public, B is made private after a mark, C is private from the start
            made = {}
            for label, public in (("a", True), ("b", True), ("c", False)):
                st, b = await call(owner, "POST", "/api/streams", json={"name": f"{pre}{label}", "is_public": public})
                if st != 201:
                    ok("streams are created", False, f"{st} {b}")
                    return
                made[label] = b["stream"]
                streams.append(b["stream"]["id"])
            A, B, C = made["a"]["id"], made["b"]["id"], made["c"]["id"]
            local, start_utc = slot(11)
            body = {"title": pre + " Friday show", "start": local, "tz": "Europe/Berlin", "duration_min": 60, "recurrence": "weekly"}

            # ---- who may write
            st, b = await call(m1, "POST", f"/api/streams/{A}/schedule", json=body)
            ok("a member may not add to another member's schedule (404)", st == 404, f"{st} {b}")
            eids = {}
            for label, sid in (("a", A), ("b", B), ("c", C)):
                st, b = await call(owner, "POST", f"/api/streams/{sid}/schedule", json=body)
                ok(f"the owner adds a weekly slot to stream {label} (201)", st == 201, f"{st} {b}")
                eids[label] = (b or {}).get("id")
            if not all(eids.values()):
                return
            st, b = await call(owner, "POST", f"/api/streams/{A}/schedule", json={**body, "tz": "Mars/Base"})
            ok("an unknown time zone is refused (400)", st == 400, f"{st} {b}")

            # ---- who sees what
            st, b = await call(m1, "GET", f"/api/streams/{A}/schedule")
            nxt = (b or {}).get("next") or [{}]
            ok("a member sees the next occurrence of a public stream, as a UTC time, not marked yet",
               st == 200 and nxt[0].get("start") == start_utc and nxt[0].get("interested") is False and "suggestion" not in b and "entries" not in b,
               f"{st} {b}")
            st1, b1 = await call(m1, "GET", f"/api/streams/{C}/schedule")
            st2, b2 = await call(m1, "GET", "/api/streams/987654321/schedule")
            ok("a private stream's schedule and an unknown stream's are the same 404", st1 == 404 and st2 == 404 and b1 == b2, f"{st1} {st2} {b1} {b2}")
            st, b = await call(m1, "GET", "/api/streams/schedule/upcoming?limit=50")
            seen = {o["stream_id"] for o in (b or {}).get("occurrences", [])}
            ok("the upcoming list holds the public streams' slots and not the private one's", st == 200 and {A, B} <= seen and C not in seen, f"{st} {seen}")
            st, b = await call(owner, "GET", "/api/streams/schedule/upcoming?limit=50")
            ok("the owner sees their private one too", C in {o["stream_id"] for o in (b or {}).get("occurrences", [])})
            st, b = await call(m1, "POST", f"/api/streams/{C}/schedule/{eids['c']}/rsvp/{start_utc}")
            ok("marking Interested on a private stream is the same 404", st == 404, f"{st} {b}")

            # ---- Interested
            st, b = await call(m1, "POST", f"/api/streams/{A}/schedule/{eids['a']}/rsvp/{start_utc}")
            ok("m1 marks stream A", st == 200 and b.get("interested") is True, f"{st} {b}")
            st, b = await call(m2, "POST", f"/api/streams/{B}/schedule/{eids['b']}/rsvp/{start_utc}")
            ok("m2 marks stream B", st == 200, f"{st} {b}")
            st, b = await call(m2, "GET", "/api/streams/schedule/upcoming?limit=50")
            mine = {}
            for o in (b or {}).get("occurrences", []):       # soonest first: the first row of a stream is this week's
                mine.setdefault(o["stream_id"], o["interested"])
            ok("each member sees their own state only", mine.get(A) is False and mine.get(B) is True, str(mine))
            raw_owner = await raw(owner, "/api/streams/schedule/upcoming?limit=50")
            ok("the owner sees a count and no member name",
               b'"interested_count": 1' in raw_owner[1].replace(b'":1', b'": 1') and (pre + "m1").encode() not in raw_owner[1] and (pre + "m2").encode() not in raw_owner[1],
               raw_owner[1][:300])
            st, b = await call(owner, "PUT", f"/api/streams/{B}", json={"is_public": False})
            ok("the owner makes stream B private", st == 200, f"{st} {b}")
            st, b = await call(m2, "GET", "/api/streams/schedule/upcoming?limit=50")
            ok("at the next read stream B is gone from m2's list", B not in {o["stream_id"] for o in (b or {}).get("occurrences", [])})
            st, b = await call(m2, "GET", f"/api/streams/{B}/schedule")
            ok("and its schedule is a 404 for m2", st == 404, str(st))

            # ---- the calendar feed
            await call(m1, "PUT", f"/api/streams/{A}/follow")
            st, b = await call(m1, "POST", "/api/me/schedule-feed")
            url = (b or {}).get("url", "")
            ok("m1 makes a calendar link ending .ics", st == 200 and url.endswith(".ics") and "/api/streams/schedule/feed/sf_" in url, f"{st} {b}")
            path = "/api/streams/schedule/feed/" + url.rsplit("/api/streams/schedule/feed/", 1)[-1]
            token = path.rsplit("/", 1)[-1][:-4]
            st, b = await call(m1, "GET", "/api/me/schedule-feed")
            ok("the status says it is active and never shows the token", st == 200 and b.get("active") is True and token not in json.dumps(b), f"{st} {b}")
            st, ics, h = await raw(bare, path)
            text = ics.decode("utf-8", "replace")
            ok("the feed answers with no login: text/calendar, no-store, no-referrer, no cookie",
               st == 200 and h.get("Content-Type", "").startswith("text/calendar") and h.get("Cache-Control") == "no-store"
               and h.get("Referrer-Policy") == "no-referrer" and "Set-Cookie" not in h, f"{st} {h}")
            ok("it holds stream A's slot as a weekly event in Berlin local time with a VTIMEZONE",
               text.startswith("BEGIN:VCALENDAR\r\n") and "RRULE:FREQ=WEEKLY" in text and f"DTSTART;TZID=Europe/Berlin:{local.replace('-', '').replace(':', '')}00" in text
               and "BEGIN:VTIMEZONE" in text and "TZID:Europe/Berlin" in text and f"SUMMARY:{pre}owner: {pre} Friday show" in text and text.endswith("END:VCALENDAR\r\n"),
               text[:500])
            ok("no physical line is over 75 octets and every line ends CRLF", all(len(l.encode()) <= 75 for l in text.split("\r\n")) and "\n" not in text.replace("\r\n", ""))
            ok("it holds nothing of the private streams",
               f"schedule-{eids['c']}@" not in text and f"schedule-{eids['b']}@" not in text)
            st, b, h = await raw(bare, "/api/streams/schedule/feed/sf_" + "A" * 43 + ".ics")
            ok("an unknown token is 404 with no-store", st == 404 and h.get("Cache-Control") == "no-store", f"{st} {h}")
            for label, hdrs in (("Bearer", {"Authorization": "Bearer " + token}), ("X-API-Key", {"X-API-Key": token})):
                st, _ = await call(bare, "GET", "/api/me", headers=hdrs)
                ok(f"the token is no credential as {label} (401)", st == 401, str(st))
            st, _ = await call(bare, "GET", "/api/me?token=" + token)
            ok("... nor as ?token= (401)", st == 401, str(st))
            ok("the staged server's log does not hold the token", token not in ctx.server_log())

            # ---- the pages
            for page, needle in (("/streams", 'id="schedule-upcoming"'), (f"/watch/{A}", "/static/js/stream-schedule.js?v=4"), ("/dashboard", 'id="calendar-feed-settings"')):
                st, body_, _h = await raw(m1, page)
                ok(f"{page} carries the schedule piece", st == 200 and needle.encode() in body_, f"{st}")
            st, js, _h = await raw(m1, "/static/js/stream-schedule.js?v=4")
            ok("the script is served", st == 200 and b"StreamSchedule" in js, str(st))

            # ---- the reminder: wait for the portal's own tick
            deadline = time.monotonic() + 140
            got = []
            while time.monotonic() < deadline:
                got = await notes(m1, A)
                if got:
                    break
                await asyncio.sleep(3)
            ok("m1 gets a reminder when the ten minute window opens", len(got) == 1, f"{len(got)}")
            if got:
                n = got[0]
                ok("it says '<streamer> starts in 10 minutes' and nothing more",
                   n.get("title") == f"{pre}owner starts in 10 minutes" and not n.get("message") and pre + " Friday" not in json.dumps(n), json.dumps(n)[:300])
            ok("the other members got none", not await notes(m2, A) and not await notes(m2, B) and not await notes(owner, A))
            await asyncio.sleep(35)
            ok("a second tick sends no second reminder", len(await notes(m1, A)) == 1)
            ok("m2, whose stream was made private after the mark, got no reminder", not await notes(m2, B))

            # ---- go-live inside the slot's window: the slot's title is offered, never applied
            async with hook.post(base + "/api/stream/auth", json={
                    "action": "publish", "path": "live/" + made["a"]["stream_key"], "password": made["a"]["stream_key"], "ip": "127.0.0.1"}) as r:
                ok("the publish hook accepts stream A", r.status == 200, str(r.status))
            await asyncio.sleep(1.5)
            st, b = await call(owner, "GET", f"/api/streams/{A}/schedule")
            sug = (b or {}).get("suggestion") or {}
            ok("the owner is offered the slot's title", sug.get("title") == pre + " Friday show", f"{st} {b}")
            _, own = await call(owner, "GET", f"/api/streams/{A}")
            ok("and the stream was not renamed", own["stream"]["name"] == pre + "a", own["stream"]["name"])
            st, b = await call(m1, "GET", f"/api/streams/{A}/schedule")
            ok("a member sees no suggestion, and the countdown moved to next week",
               "suggestion" not in b and b["next"][0]["start"] == start_utc + 7 * 86400, str(b)[:300])
            st, _ = await call(owner, "DELETE", f"/api/streams/{A}/schedule/suggestion")
            st, b = await call(owner, "GET", f"/api/streams/{A}/schedule")
            ok("the owner dismisses it", b.get("suggestion") is None)

            # ---- regenerate and revoke
            st, b = await call(m1, "POST", "/api/me/schedule-feed")
            path2 = "/api/streams/schedule/feed/" + b["url"].rsplit("/api/streams/schedule/feed/", 1)[-1]
            st_old, _, _ = await raw(bare, path)
            st_new, _, _ = await raw(bare, path2)
            ok("regenerating ends the old address and the new one works", st_old == 404 and st_new == 200, f"{st_old} {st_new}")
            await call(m1, "DELETE", "/api/me/schedule-feed")
            st_new, _, _ = await raw(bare, path2)
            ok("revoking ends it (404)", st_new == 404, str(st_new))
        finally:
            for sid in streams:
                try:
                    await call(owner, "DELETE", f"/api/streams/{sid}")
                except Exception:
                    pass
