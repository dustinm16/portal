"""Alert rules for staff, private contexts, failed-code bursts, update announcements and an
unreadable certificate: sub-caps bind only non-staff actors (a staff action, a staff-account
subject and every operations alert bypass them, and the global cap keeps a reserve that
member-caused alerts cannot use), the suppressed notice names what was held back and reaches
every system hook with an alert subscribed, a private channel's name stays out of non-generic
formats, 2fa_failed feeds the burst counter and a burst held back is still recorded once, an
update is announced only when something was sent, and an unreadable certificate raises one
in-portal notice a day. Fake clock and delivery; nothing is sent anywhere.

Run: venv/bin/python tests/test_alert_staff.py
"""

import asyncio
import datetime as dt
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import alerts  # noqa: E402
import webhook_formats as wf  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Env:
    def __init__(self, hooks_reached=1, notify=False):
        self.t = 1000.0
        self.fired = []          # (event, payload)
        self.notified = []
        self.settings = {}
        self.records = []
        self.reached = hooks_reached
        alerts.reset_state()
        alerts._clock = lambda: self.t

        async def quick_sleep(_s):
            await asyncio.sleep(0)

        alerts._sleep = quick_sleep
        alerts.bind(fire=self.fire, notify=self.notify if notify else None, get_setting=self.get,
                    set_setting=self.set)
        alerts.bind_record(self.record)

    async def fire(self, event, payload):
        self.fired.append((event, payload))
        return self.reached

    async def notify(self, event, title, summary):
        self.notified.append((event, title, summary))

    async def get(self, key):
        return self.settings.get(key)

    async def set(self, key, value):
        self.settings[key] = value

    async def record(self, event, details, ip=None):
        self.records.append(event)

    async def settle(self):
        for _ in range(5):
            await asyncio.sleep(0)
        while alerts._tasks:
            await asyncio.gather(*list(alerts._tasks), return_exceptions=True)

    def count(self, event):
        return sum(1 for e, _ in self.fired if e == event)


def mod(action, actor, target, role=None, **kw):
    return alerts.moderation_action(action, actor=f"u{actor}", target=f"u{target}", anonymous=False,
                                    actor_id=actor, target_id=target, actor_role=role, **kw)


async def main():
    # ---- 1. members exhaust their buckets, then staff actions still alert
    env = Env()
    alerts.set_staff([900, 901], ["boss", "mod1"])
    for i in range(40):
        mod("ban", 7, 1000 + i)
        alerts.automod_triggered(rule_id=i, rule_name="r", rule_action="delete", member=f"m{i}",
                                 member_id=2000 + i, anonymous=False)
        alerts.on_security_event("api_key_created", user_id=3000 + i, username=f"k{i}", details={"name": "k"})
        alerts.on_security_event("2fa_disabled", user_id=4000 + i, username=f"n{i}")
    for a in range(30):
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure(f"198.51.{a}.7", None)
    await env.settle()
    member_total = len(alerts._sent)
    check("members saturate every bucket", env.count("moderation.action") + env.count("automod.triggered")
          == alerts.SUB_CAPS["member"] and env.count("2fa.disabled") == alerts.SUB_CAPS["2fa.disabled"]
          and env.count("apikey.created") == alerts.SUB_CAPS["apikey.created"]
          and env.count("auth.login_failed_burst") == alerts.SUB_CAPS["auth.login_failed_burst"])
    check("member-caused alerts never use the reserve",
          member_total <= alerts.CAP_ALERTS - alerts.MEMBER_RESERVE, str(member_total))
    check("a moderator's action still alerts", mod("timeout", 901, 5, role="moderator") is True)
    check("an admin's action (role known only from the registry) still alerts", mod("ban", 900, 6) is True)
    check("a moderator's automod hit still alerts",
          alerts.automod_triggered(rule_id=99, rule_name="r", rule_action="delete", member="mod1",
                                   member_id=901, anonymous=False, member_role="moderator") is True)
    check("2fa turned off on a staff account still alerts",
          alerts.emit("2fa.disabled", key=900, summary="x", staff=alerts.is_staff(900, "boss")) is True)
    alerts.on_security_event("api_key_created", user_id=900, username="boss", details={"name": "k"})
    alerts.on_security_event("2fa_disabled", user_id=901, username="mod1")
    for _ in range(alerts.BURST_THRESHOLD):
        alerts.note_login_failure("203.0.113.77", "boss")
    for i in range(3):
        alerts.note_login_failure(f"203.0.113.{i}", "boss")   # other addresses, same staff account
    for _ in range(alerts.BURST_THRESHOLD):
        alerts.note_login_failure("203.0.113.88", "mod1")
    await env.settle()
    check("a staff account's api key and 2fa change alert after the buckets are full",
          env.count("apikey.created") == alerts.SUB_CAPS["apikey.created"] + 1
          and env.count("2fa.disabled") == alerts.SUB_CAPS["2fa.disabled"] + 2)
    check("a failed-sign-in burst against a staff account name alerts (per account, not per address)",
          env.count("auth.login_failed_burst") == alerts.SUB_CAPS["auth.login_failed_burst"] + 2,
          str(env.count("auth.login_failed_burst")))
    check("operations alerts bypass the sub-caps",
          alerts.emit("service.health_changed", key=("svc", 1), summary="x") is True
          and alerts.emit("backup.failed", summary="x") is True
          and alerts.emit("cert.renewal_failed", key="k", summary="x") is True
          and alerts.emit("update.available", key="u", cooldown=0.0, summary="x") is True
          and alerts.emit("gameserver.crashed", key=("gs", 1), summary="x") is True)
    check("staff alerts did not count against the member buckets",
          all(len(r) <= alerts.SUB_CAPS[b] for b, r in alerts._sent_by.items()
              if b != alerts.STAFF_BURST_BUCKET))

    # rotating addresses cannot repeat a staff-account burst inside its cooldown
    env = Env()
    alerts.set_staff([900], ["boss"])
    for a in range(20):
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure(f"198.18.{a}.1", "boss")
    await env.settle()
    check("bursts against one staff account rotate no further than one alert per cooldown",
          env.count("auth.login_failed_burst") == 1, str(env.count("auth.login_failed_burst")))
    check("a non-staff account name gets no bypass",
          not alerts.is_staff(None, "someone") and alerts.is_staff(None, "boss"))

    # a member whose name differs from a staff name only in letter case is not staff
    # (account names are case-sensitive and unique)
    env = Env()
    alerts.set_staff([900], ["boss"])
    check("a known non-staff id with a case variant of a staff name is not staff",
          not alerts.is_staff(50, "BOSS") and alerts.is_staff(900, "boss") and alerts.is_staff(900, "other"))
    check("without an id the name must match exactly (no case folding)",
          not alerts.is_staff(None, "BOSS") and not alerts.is_staff(None, "Boss"))
    for i in range(40):
        mod("ban", 7, 1000 + i)
        alerts.on_security_event("api_key_created", user_id=3000 + i, username=f"k{i}", details={"name": "k"})
        alerts.on_security_event("2fa_disabled", user_id=4000 + i, username=f"n{i}")
    for i in range(8):
        env.t += 61.0          # past the per-account cooldown, 8 minutes: inside the 10 minute window
        alerts.on_security_event("api_key_created", user_id=50, username="BOSS", details={"name": "k"})
        alerts.on_security_event("2fa_disabled", user_id=50, username="BOSS")
    await env.settle()
    check("a lookalike member does not get past the sub-caps",
          env.count("apikey.created") <= alerts.SUB_CAPS["apikey.created"]
          and env.count("2fa.disabled") <= alerts.SUB_CAPS["2fa.disabled"]
          and len(alerts._sent) <= alerts.CAP_ALERTS - alerts.MEMBER_RESERVE,
          f"{env.count('apikey.created')} {env.count('2fa.disabled')} {len(alerts._sent)}")
    # the burst ring and cooldown of 'Boss' are not those of the staff account 'boss'
    env = Env()
    alerts.set_staff([900], ["boss"])
    for _ in range(alerts.BURST_THRESHOLD):
        alerts.note_login_failure("203.0.113.5", "Boss")
    await env.settle()
    check("a burst on the lookalike alerts once", env.count("auth.login_failed_burst") == 1,
          str(env.count("auth.login_failed_burst")))
    env.t += 30.0
    for i in range(alerts.BURST_THRESHOLD):
        alerts.note_login_failure(f"198.51.100.{i}", "boss")
    await env.settle()
    check("the lookalike's cooldown does not silence the burst on the staff account",
          env.count("auth.login_failed_burst") == 2, str(env.count("auth.login_failed_burst")))
    check("an administrator's ban still alerts after the lookalike's attempts",
          mod("ban", 900, 1, role="admin") is True)
    await env.settle()

    # the reserve: member-caused alerts stop at CAP - reserve, others go on to CAP
    env = Env()
    alerts.set_staff([900], ["boss"])
    for i in range(alerts.CAP_ALERTS - alerts.MEMBER_RESERVE):
        alerts.emit("role.changed", key=i, summary="x")
    check("with the reserve all that is left, a member-caused alert is held back",
          mod("ban", 7, 1) is False)
    check("a staff action still alerts", mod("ban", 900, 1, role="admin") is True)
    check("a role change still alerts", alerts.emit("role.changed", key="late", summary="x") is True)
    await env.settle()

    # ---- the notice names each kind with its count and reaches hooks with any alert subscribed
    env = Env()
    for i in range(alerts.CAP_ALERTS):
        alerts.emit("role.changed", key=i, summary="x")
    for i in range(4):
        alerts.emit("backup.failed", key=f"b{i}", summary="x")
    alerts.emit("service.health_changed", key=("svc", 1), summary="x")
    await env.settle()
    notice = [p for e, p in env.fired if e == "alerts.suppressed"]
    check("one notice for the trip", len(notice) == 1, str(len(notice)))
    s = notice[0]["summary"] if notice else ""
    check("the notice names each kind held back with its count",
          "backup.failed: 4" in s and "service.health_changed: 1" in s and "role.changed" not in s, s)
    check("the notice summary is within the limit and says why", len(s) <= alerts.SUMMARY_LIMIT and "Limit of" in s, s)
    check("a system hook with any alert event subscribed receives the notice",
          wf.event_subscribed(["backup.ok"], "alerts.suppressed", kind="system", fmt="ntfy")
          and wf.event_subscribed(["moderation.action", "message.created"], "alerts.suppressed", kind="system"))
    check("a hook with no alert subscribed, a '*' hook and a user hook do not",
          not wf.event_subscribed(["message.created"], "alerts.suppressed", kind="system")
          and not wf.event_subscribed(["*"], "alerts.suppressed", kind="system")
          and not wf.event_subscribed(["backup.ok", "alerts.suppressed"], "alerts.suppressed", kind="user")
          and not wf.event_subscribed(["backup.ok"], "alerts.suppressed", kind="user"))
    check("the other alerts still need to be listed by name",
          not wf.event_subscribed(["backup.ok"], "backup.failed", kind="system"))

    # many kinds: every kind is named or counted, the list comes first and the summary is not cut
    env = Env()
    for i in range(alerts.CAP_ALERTS):
        alerts.emit("role.changed", key=i, summary="x")
    kinds = ["ip.blocked", "moderation.action", "automod.triggered", "auth.login_failed_burst", "2fa.disabled",
             "apikey.created", "update.available", "cert.renewal_failed", "backup.ok", "backup.failed",
             "gameserver.crashed", "service.health_changed", "cert.expiring"]
    for n, kind in enumerate(kinds, 1):
        for j in range(n):
            alerts.emit(kind, key=(kind, j), summary="x")
    await env.settle()
    notice = [p for e, p in env.fired if e == "alerts.suppressed"]
    s = notice[0]["summary"] if notice else ""
    check("with many kinds the notice starts with the list and is not cut mid-word",
          s.startswith("Held back (") and len(s) <= alerts.SUMMARY_LIMIT and not s.endswith("avai"), s)
    named = sum(1 for k in kinds if f"{k}: " in s)
    import re
    more = re.search(r"and (\d+) more kinds", s)
    check("every kind is named or counted in the remainder",
          named + (int(more.group(1)) if more else 0) == len(kinds), f"{named} {more and more.group(0)} {s}")
    check("the commonest kind is named first", f"{kinds[-1]}: {len(kinds)}" in s.split(": ", 1)[1][:60], s)

    # ---- 3. a private context keeps its name out of the non-generic formats
    env = Env()
    mod("ban", 7, 8, role="admin", channel="secret-room", reason="spam", private=True)
    await env.settle()
    payload = env.fired[-1][1]
    check("the payload keeps the name for the generic format (details) and carries a third-party version",
          payload["details"].get("Channel") == "secret-room" and "third_party" in payload)
    gen = wf.format_payload("generic", "moderation.action", payload, include_details=True, secret="s")
    check("generic is sent the original summary and details", b"secret-room" in gen.body, gen.body.decode())
    check("generic does not leak the third-party block", b"third_party" not in gen.body)
    for fmt in ("discord", "slack", "ntfy", "gotify"):
        kw = {"secret_config": {"token": "t"}} if fmt == "gotify" else {}
        req = wf.format_payload(fmt, "moderation.action", payload, include_details=True, **kw)
        text = req.body.decode()
        check(f"{fmt}: no channel name, 'in a private channel' said, also with details",
              "secret-room" not in text and "in a private channel" in text, text[:300])
    mod("ban", 900, 9, role="admin", channel="general", private=False)
    await env.settle()
    plain = env.fired[-1][1]
    req = wf.format_payload("discord", "moderation.action", plain, include_details=True)
    check("a public channel is named as before", "general" in req.body.decode() and "private" not in req.body.decode())
    alerts.automod_triggered(rule_id=1, rule_name="rule", rule_action="delete", member="m", member_id=5,
                             anonymous=False, channel="secret-room", private=True)
    await env.settle()
    req = wf.format_payload("slack", "automod.triggered", env.fired[-1][1], include_details=True)
    check("automod from a private channel: no name in a non-generic format",
          "secret-room" not in req.body.decode() and "private channel" in req.body.decode())

    # ---- 4. 2fa_failed feeds the burst counter, a held burst is still recorded once
    env = Env()
    for _ in range(alerts.BURST_THRESHOLD):
        alerts.on_security_event("2fa_failed", ip="198.51.100.9", username="someone")
    await env.settle()
    check("five wrong second-factor codes make a burst", env.count("auth.login_failed_burst") == 1)
    for i in range(3):
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.on_security_event("login_failed", ip="198.51.100.9", username="someone")
    await env.settle()
    check("password and code failures count together (a mixed burst trips as well)",
          env.count("auth.login_failed_burst") == 1)
    check("every burst is recorded once, the cooldown-held ones too", env.records.count("login_failed_burst") == 4,
          str(env.records))
    env = Env()
    for _ in range(3):
        alerts.on_security_event("login_failed", ip="198.51.100.10", username="x1")
    for _ in range(2):
        alerts.on_security_event("2fa_failed", ip="198.51.100.10", username="x2")
    await env.settle()
    check("failures of both kinds from one address add up", env.count("auth.login_failed_burst") == 1)

    # ---- 6. update.available is announced only when something was sent
    env = Env(hooks_reached=0, notify=False)
    data = {"portal": {"update_available": True, "latest": "9.9.9", "current": "1.0.0"}}
    n = await alerts.note_updates(data)
    await env.settle()
    check("no hook and no in-portal notice: not announced", n == 0 and not alerts._announced
          and "9.9.9" not in env.settings.get(alerts.UPDATE_STATE_KEY, ""), str(env.settings))
    env.reached = 1
    n = await alerts.note_updates(data)
    check("a later check, now with a hook that is sent it, announces", n == 1)
    check("and a check after that sends nothing", await alerts.note_updates(data) == 0)
    env = Env(hooks_reached=0, notify=True)
    check("the in-portal notice alone counts as announced", await alerts.note_updates(data) == 1)
    env.settings.clear()
    env = Env(hooks_reached=0, notify=True)
    env.settings["alert_notify_update_available"] = "0"
    check("notice switched off and no hook: not announced", await alerts.note_updates(data) == 0)

    # ---- 6. an unreadable certificate raises one in-portal notice per day
    env = Env(notify=True)
    when = dt.datetime(2026, 11, 19, 3, 0, tzinfo=dt.timezone.utc)
    r = await alerts.check_certificate("/nonexistent/cert.pem", when)
    check("an unreadable certificate file: nothing alerted, one notice raised",
          r is None and len(env.notified) == 1 and "certificate" in env.notified[0][2].lower(), str(env.notified))
    await alerts.check_certificate("/nonexistent/cert.pem", when + dt.timedelta(hours=5))
    check("a second check the same day raises none", len(env.notified) == 1)
    await alerts.check_certificate("/nonexistent/cert.pem", when + dt.timedelta(days=1))
    check("the next day raises one more", len(env.notified) == 2)
    check("no webhook alert was fired for it", env.fired == [])


asyncio.run(main())
if failures:
    print(f"\ntest_alert_staff: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_alert_staff: all checks passed")
