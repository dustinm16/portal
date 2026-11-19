"""Alert limits: composite cooldown keys, the global cap and its notice, per-event
sub-caps for the events strangers and ordinary members can trigger, and once-per-version update alerts under
overlapping checks. A fake clock and fake delivery; nothing is sent anywhere.

Run: venv/bin/python tests/test_alert_limits.py
"""

import asyncio
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import alerts  # noqa: E402

failures = []
SUB_CAPS = alerts.SUB_CAPS
MEMBER_CAP = SUB_CAPS["member"]


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Env:
    def __init__(self, slow_settings=False, virtual=False):
        self.t = 1000.0
        self.fired = []
        self.payloads = []       # (time, event, payload) of every hook delivery
        self.timers = []         # (due, future) of the virtual sleeps
        self.times = []          # (time, event) of every delivery, recorded synchronously
        self.settings = {}
        self.slow = slow_settings
        alerts.reset_state()
        alerts._clock = lambda: self.t

        async def quick_sleep(_seconds):
            await asyncio.sleep(0)

        async def virtual_sleep(seconds):
            fut = asyncio.get_running_loop().create_future()
            self.timers.append((self.t + seconds, fut))
            await fut

        alerts._sleep = virtual_sleep if virtual else quick_sleep
        real_deliver = alerts._deliver

        def deliver(alert):
            self.times.append((self.t, alert["event"]))
            real_deliver(alert)

        alerts._deliver = deliver
        self._real_deliver = real_deliver
        alerts.bind(fire=self.fire, notify=None, get_setting=self.get, set_setting=self.set)
        alerts.bind_record(None)

    async def fire(self, event, payload):
        self.fired.append(event)
        self.payloads.append((self.t, event, payload))
        return 1

    async def pump(self):
        for _ in range(8):
            await asyncio.sleep(0)

    async def advance(self, t):
        """Move the fake clock to t, waking every virtual sleep that falls due on the way."""
        await self.pump()           # let freshly spawned tasks register their sleeps at the current time
        while True:
            due = sorted((d, i) for i, (d, f) in enumerate(self.timers) if d <= t and not f.done())
            if not due:
                break
            d, i = due[0]
            self.t = max(self.t, d)
            self.timers[i][1].set_result(None)
            await self.pump()
        self.t = t
        await self.pump()

    async def get(self, key):
        if self.slow:
            await asyncio.sleep(0.01)
        return self.settings.get(key)

    async def set(self, key, value):
        if self.slow:
            await asyncio.sleep(0.01)
        self.settings[key] = value

    async def settle(self):
        for _ in range(5):
            await asyncio.sleep(0)
        while alerts._tasks:
            await asyncio.gather(*list(alerts._tasks), return_exceptions=True)

    def close(self):
        alerts._deliver = self._real_deliver


def automod(rule, member):
    return alerts.automod_triggered(rule_id=rule, rule_name="r", rule_action="delete", member=f"m{member}",
                                    member_id=member, anonymous=False)


def modact(action, actor, target):
    return alerts.moderation_action(action, actor=f"u{actor}", target=f"u{target}", anonymous=False,
                                    actor_id=actor, target_id=target)


def worst_window(times, window):
    best = 0
    for i, (t0, _) in enumerate(times):
        best = max(best, sum(1 for t, _ in times[i:] if t - t0 < window))
    return best


async def main():
    # --- composite keys are one key each
    env = Env()
    check("automod rule 1 / member 10 admitted", automod(1, 10) is True)
    check("automod rule 2 / member 20 admitted", automod(2, 20) is True)
    check("automod rule 1 / member 20 (a new pair) is admitted", automod(1, 20) is True)
    check("the same pair again is held back", automod(1, 10) is False)
    check("rule 3 / member 5 admitted", automod(3, 5) is True)
    check("rule 5 / member 3 (ids from other roles) admitted", automod(5, 3) is True)
    await env.settle()
    env.close()
    env = Env()
    check("moderation A times out B", modact("timeout", 1, 2) is True)
    check("moderation C mutes D", modact("mute", 3, 4) is True)
    check("moderation A mutes D (a new combination) is admitted", modact("mute", 1, 4) is True)
    check("the same moderation action again is held back", modact("timeout", 1, 2) is False)
    check("a list still means several independent keys",
          alerts.emit("role.changed", key=["a", "b"], summary="x") is True
          and alerts.emit("role.changed", key=["a", "c"], summary="x") is True
          and alerts.emit("role.changed", key=["a", "b"], summary="x") is False)
    check("a tuple is a single key", alerts._keys_of(("a", 1)) == (("a", 1),))
    await env.settle()
    env.close()

    # --- a notice is due whenever anything is held back, at most one per NOTICE_INTERVAL
    env = Env(virtual=True)
    rng = random.Random(7)
    t = 0.0
    n = 0
    while t < 6000:
        t += rng.expovariate(1 / 5.0)
        await env.advance(1000.0 + t)
        n += 1
        alerts.emit("role.changed", key=f"k{n}", summary="x")
    await env.advance(1000.0 + 6000 + 700)
    notice_times = [t for t, e in env.times if e == "alerts.suppressed"]
    regular = [(t, e) for t, e in env.times if e != "alerts.suppressed"]
    check("under sustained load there is a notice about every NOTICE_INTERVAL, never closer",
          len(notice_times) >= 8 and all(b - a >= alerts.NOTICE_INTERVAL - 1e-6
                                         for a, b in zip(notice_times, notice_times[1:])), str(notice_times))
    check("the first notice follows the first refusal by about NOTICE_DELAY",
          abs(notice_times[0] - (env.times[alerts.CAP_ALERTS - 1][0] + 0)) < 60 if notice_times else False,
          str(notice_times[:2]))
    check("no window holds more than CAP_ALERTS regular alerts",
          worst_window(regular, alerts.CAP_WINDOW) <= alerts.CAP_ALERTS, str(worst_window(regular, alerts.CAP_WINDOW)))
    check("no window holds more than CAP_ALERTS plus the notice in all",
          worst_window(env.times, alerts.CAP_WINDOW) <= alerts.CAP_ALERTS + 1,
          str(worst_window(env.times, alerts.CAP_WINDOW)))
    env.close()

    env = Env(virtual=True)
    for i in range(alerts.CAP_ALERTS + 3):
        alerts.emit("role.changed", key=i, summary="x")
    await env.advance(1000.0 + 10)
    check("no notice before NOTICE_DELAY", not any(e == "alerts.suppressed" for _, e in env.times))
    await env.advance(1000.0 + alerts.NOTICE_DELAY + 1)
    check("the first notice goes out NOTICE_DELAY after the first refusal",
          [e for _, e in env.times].count("alerts.suppressed") == 1)
    first = [p for _, e, p in env.payloads if e == "alerts.suppressed"][0]
    check("the notice lists the kind with its count and says the global limit held it back",
          "role.changed: 3" in first["summary"] and "Limit of" in first["summary"], first["summary"])
    await env.advance(1000.0 + alerts.CAP_WINDOW / 2)
    alerts.emit("role.changed", key="mid", summary="x")
    await env.advance(1000.0 + alerts.CAP_WINDOW + 5)
    for i in range(alerts.CAP_ALERTS + 3):
        alerts.emit("role.changed", key=f"b{i}", summary="x")
    await env.advance(env.t + alerts.NOTICE_DELAY + 1)
    check("a refusal after the interval gets its own notice about NOTICE_DELAY later",
          [e for _, e in env.times].count("alerts.suppressed") == 2)
    await env.pump()
    env.close()

    # --- strangers cannot use up the room of the other alerts
    env = Env()
    admitted = 0
    for a in range(30):
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure(f"198.51.{a}.7", None)
    bursts = sum(1 for _, e in env.times if e == "auth.login_failed_burst")
    check("thirty addresses with five failures each send only the burst sub-cap",
          bursts == SUB_CAPS["auth.login_failed_burst"], str(bursts))
    for i in range(40):
        automod(100 + i, 200 + i)
    check("automod hits stop at the member sub-cap",
          sum(1 for _, e in env.times if e == "automod.triggered") == MEMBER_CAP)
    for minute in range(8):
        env.t += 61
        alerts.note_auto_block(f"203.0.113.{minute}")
        alerts.flush_auto_blocks()
    check("automatic block alerts stop at their sub-cap",
          sum(1 for _, e in env.times if e == "ip.blocked") == SUB_CAPS["ip.blocked:auto"])
    env.t = 1000.0 + 61 * 8
    alerts.service_event("service.health_changed", {"id": 1, "name": "svc", "state": "down", "status": "x",
                                                    "failed_checks": 3})
    down = [e for _, e in env.times if e == "service.health_changed"]
    check("a service 'down' alert is still admitted after all three strangers' paths are saturated", len(down) == 1)
    check("a role change is still admitted",
          alerts.emit("role.changed", key=[("target", 1)], summary="x") is True)
    check("a manual block is not held by the automatic-block sub-cap",
          alerts.emit("ip.blocked", key=("manual", "1.2.3.4"), summary="x") is True)
    await env.settle()
    check("the sub-cap trips sent a notice", any(e == "alerts.suppressed" for _, e in env.times))
    check("the reserved room is real: sub-caps plus notice leave room for the rest",
          alerts.CAP_ALERTS - sum(SUB_CAPS.values()) - 1 >= alerts.MEMBER_RESERVE - 1
          and sum(SUB_CAPS.values()) <= alerts.CAP_ALERTS - alerts.MEMBER_RESERVE)
    env.close()

    # --- what an ordinary member can set off cannot use up the room either
    env = Env()
    admitted = sum(1 for i in range(40) if modact("ban", 7, 1000 + i))
    check("forty bans by one member (new target each time) admit only the member sub-cap",
          admitted == MEMBER_CAP, str(admitted))
    check("a role change right after is still admitted",
          alerts.emit("role.changed", key=[("target", 1)], summary="x") is True)
    env.close()

    env = Env()
    for i in range(60):
        env.t += 61                       # every cooldown has passed
        alerts.on_security_event("api_key_created", user_id=5, username="m5", details={"name": f"k{i}"})
        alerts.on_security_event("2fa_disabled", user_id=5, username="m5")
        if i % 9 == 0:
            env.t += 600
    # a member who creates a key and turns 2FA off every minute for an hour
    worst = worst_window([x for x in env.times if x[1] in ("apikey.created", "2fa.disabled")], alerts.CAP_WINDOW)
    check("a key a minute and a 2FA toggle a minute never send more than their sub-caps per window",
          worst <= SUB_CAPS["apikey.created"] + SUB_CAPS["2fa.disabled"], str(worst))
    env.close()

    # --- moderation cannot silence the account-security alerts (member bans, then 2FA is turned off)
    env = Env()
    admitted = sum(1 for i in range(40) if modact("ban", 7, 1000 + i))
    check("a member's bans fill only the moderation bucket", admitted == MEMBER_CAP, str(admitted))
    for i in range(40):
        automod(500 + i, 600 + i)
    alerts.on_security_event("2fa_disabled", user_id=50, username="victim")
    alerts.on_security_event("api_key_created", user_id=51, username="victim2", details={"name": "k"})
    check("2fa.disabled and apikey.created are still sent after the moderation bucket is full",
          [e for _, e in env.times if e in ("2fa.disabled", "apikey.created")] == ["2fa.disabled", "apikey.created"],
          str(env.times[-4:]))
    check("the account-security events do not count against the moderation bucket",
          "2fa.disabled" not in alerts.BUCKET_OF and "apikey.created" not in alerts.BUCKET_OF)
    # the reverse: spamming API keys (another account each time) cannot hold back 2fa.disabled
    for i in range(20):
        alerts.on_security_event("api_key_created", user_id=100 + i, username=f"k{i}", details={"name": "k"})
    alerts.on_security_event("2fa_disabled", user_id=52, username="victim3")
    check("API key alerts at their cap do not hold back a 2fa.disabled alert",
          sum(1 for _, e in env.times if e == "2fa.disabled") == 2
          and sum(1 for _, e in env.times if e == "apikey.created") == SUB_CAPS["apikey.created"])
    await env.settle()
    env.close()

    # --- a second, different role change of the same account within the cooldown is still sent
    env = Env()
    role = dict(target_user_id=9, target_username="tgt")
    alerts.on_security_event("role_changed", user_id=1, username="adm", details=dict(role, old_role="user", new_role="admin"))
    env.t += 30
    alerts.on_security_event("role_changed", user_id=1, username="adm",
                             details=dict(role, old_role="admin", new_role="superadmin"))
    check("user to admin, then admin to superadmin 30 seconds later: both sent",
          [e for _, e in env.times] == ["role.changed", "role.changed"], str(env.times))
    env.t += 10
    alerts.on_security_event("role_changed", user_id=1, username="adm",
                             details=dict(role, old_role="admin", new_role="superadmin"))
    check("the same change repeated inside the cooldown is still held back",
          len(env.times) == 2, str(env.times))
    alerts.on_security_event("role_changed", user_id=1, username="adm",
                             details=dict(target_user_id=10, target_username="other", old_role="user", new_role="admin"))
    check("another account's change is not held back", len(env.times) == 3, str(env.times))
    await env.settle()
    env.close()

    env = Env()
    for a in range(30):
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure(f"198.51.{a}.9", None)
    for i in range(40):
        modact("ban", 8, 2000 + i)
        automod(300 + i, 400 + i)
        alerts.on_security_event("api_key_created", user_id=100 + i, username=f"m{i}", details={"name": "k"})
        alerts.on_security_event("2fa_disabled", user_id=200 + i, username=f"n{i}")
    for minute in range(8):
        env.t += 61
        alerts.note_auto_block(f"203.0.113.{minute}")
        alerts.flush_auto_blocks()
    env.t = 1000.0 + 61 * 8
    check("every stranger and member path saturated: role.changed still admitted",
          alerts.emit("role.changed", key=[("target", 3)], summary="x") is True)
    check("backup.failed still admitted", alerts.emit("backup.failed", summary="x") is True)
    check("a service down alert still admitted",
          alerts.emit("service.health_changed", key=("svc", 1), summary="x") is True)
    check("a certificate alert still admitted", alerts.emit("cert.renewal_failed", key="request", summary="x") is True)
    check("a manual block still admitted", alerts.emit("ip.blocked", key=("manual", "9.9.9.9"), summary="x") is True)
    await env.settle()
    env.close()

    # --- every event an ordinary member or a stranger can set off has a capped bucket
    env = Env()
    member_events = {"moderation.action", "automod.triggered", "apikey.created", "2fa.disabled"}
    stranger_buckets = {"auth.login_failed_burst", "ip.blocked:auto"}
    for ev in member_events:
        check(f"{ev} counts against a capped bucket", alerts.BUCKET_OF.get(ev, ev) in SUB_CAPS)
    check("the stranger paths have their caps", stranger_buckets <= set(SUB_CAPS))
    check("BUCKET_OF names only known events and known buckets",
          set(alerts.BUCKET_OF) <= alerts.EVENT_NAMES and set(alerts.BUCKET_OF.values()) <= set(SUB_CAPS))
    env.close()

    # a burst held back by a cap is still written to the security log
    env = Env()
    recs = []

    async def rec(event, details, ip=None):
        recs.append(event)

    alerts.bind_record(rec)
    for a in range(SUB_CAPS["auth.login_failed_burst"] + 3):
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure(f"198.18.{a}.9", None)
    await env.settle()
    check("every burst is recorded, also when the cap holds its alert back",
          recs.count("login_failed_burst") == SUB_CAPS["auth.login_failed_burst"] + 3, str(recs))
    alerts.bind_record(None)
    env.close()

    # --- a member keeps one cap tripped, later refusals are still reported
    env = Env(virtual=True)
    t0 = env.t
    cap = SUB_CAPS["apikey.created"]
    for r in range(3):
        await env.advance(t0 + r * 540)
        for i in range(cap + 1):
            alerts.on_security_event("api_key_created", user_id=500 + r * 10 + i, username=f"m{r}{i}",
                                     details={"name": "k"})
    await env.advance(t0 + 20 * 60)
    for i in range(alerts.CAP_ALERTS):
        alerts.emit("role.changed", key=("fill", i), summary="x")
    held_before = len([1 for _, e in env.times if e == "alerts.suppressed"])
    for i in range(10):
        alerts.emit("service.health_changed", key=("svc", i), summary="x")
    alerts.moderation_action("ban", actor="boss", target="troll", anonymous=False, actor_id=1, target_id=2,
                             actor_role="admin")
    await env.advance(t0 + 20 * 60 + 11 * 60)
    notices = [(t, p) for t, e, p in env.payloads if e == "alerts.suppressed"]
    late = [p for t, p in notices if t > t0 + 20 * 60]
    text = " | ".join(p["summary"] + " " + str(p["details"]) for p in late)
    check("a member who trips a cap every 9 minutes did not mute the notices (one per interval)",
          len(notices) >= 3 and all(b[0] - a[0] >= alerts.NOTICE_INTERVAL - 1e-6
                                    for a, b in zip(notices, notices[1:])), str([t - t0 for t, _ in notices]))
    check("the notice after the outage names the ten service alerts", "service.health_changed: 10" in text, text)
    check("and the staff moderation alert", "moderation.action: 1" in text, text)
    check("and says the global limit held them back", "global" in text.lower() or "Limit of" in text, text)
    check("the counts were cleared by that notice, the next is quiet",
          held_before >= 1 and alerts.suppressed_count() == 0, str(alerts.suppressed_count()))
    first_kind = notices[0][1]
    check("the first notice (the member's cap) says it was a per-kind limit",
          "per-kind" in first_kind["summary"].lower() and "apikey.created" in first_kind["summary"],
          first_kind["summary"])
    env.close()

    # --- the reason is accurate: reserve, and mixed reasons per kind
    env = Env(virtual=True)
    for i in range(alerts.CAP_ALERTS - alerts.MEMBER_RESERVE):
        alerts.emit("role.changed", key=("r", i), summary="x")
    alerts.moderation_action("ban", actor="m", target="x", anonymous=False, actor_id=900, target_id=901)
    await env.advance(env.t + alerts.NOTICE_DELAY + 1)
    reserve = [p for _, e, p in env.payloads if e == "alerts.suppressed"]
    check("an alert held back by the reserve says so", reserve and "Reserve" in reserve[0]["summary"]
          and "Limit of" not in reserve[0]["summary"], str(reserve))
    env.close()
    env = Env(virtual=True)
    for i in range(alerts.CAP_ALERTS - alerts.MEMBER_RESERVE):
        alerts.emit("role.changed", key=("r", i), summary="x")
    alerts.moderation_action("ban", actor="m", target="x", anonymous=False, actor_id=900, target_id=901)
    for i in range(alerts.MEMBER_RESERVE):
        alerts.emit("role.changed", key=("g", i), summary="x")
    alerts.emit("backup.failed", key="late", summary="x")
    await env.advance(env.t + alerts.NOTICE_DELAY + 1)
    mixed = [p for _, e, p in env.payloads if e == "alerts.suppressed"]
    s_ = mixed[0]["summary"] if mixed else ""
    check("mixed reasons are named per kind", "moderation.action: 1 (reserve)" in s_ and "backup.failed: 1 (global limit)" in s_, s_)
    env.close()

    # --- strangers hammering staff account names cannot fill the reserve
    use = getattr(alerts, "STAFF_BURST_RESERVE_USE", 5)
    names = [f"staff{i}" for i in range(40)]
    env = Env()
    alerts.set_staff(ids=(), names=names)
    for n_ in names:
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure("198.51.100.1", n_)
    staff_bursts = sum(1 for _, e in env.times if e == "auth.login_failed_burst")
    check("staff-subject bursts use at most STAFF_BURST_RESERVE_USE (5) of the reserved slots",
          use == 5 and staff_bursts == alerts.CAP_ALERTS - alerts.MEMBER_RESERVE + use, str(staff_bursts))
    ok = sum(1 for i in range(alerts.CAP_ALERTS) if alerts.emit("service.health_changed", key=("s", i), summary="x"))
    check("operations alerts keep the other reserved slots", ok == alerts.MEMBER_RESERVE - use, str(ok))
    env.close()
    env = Env()
    alerts.set_staff(ids=(), names=names)
    for n_ in names:
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure("198.51.100.2", n_)
    ok = sum(1 for i in range(alerts.CAP_ALERTS)
             if alerts.moderation_action("ban", actor="boss", target=f"t{i}", anonymous=False, actor_id=1,
                                         target_id=100 + i, actor_role="admin"))
    check("staff-actor alerts keep the other reserved slots", ok == alerts.MEMBER_RESERVE - use, str(ok))
    env.close()
    env = Env()
    alerts.set_staff(ids=(), names=names)
    for i in range(alerts.CAP_ALERTS - alerts.MEMBER_RESERVE):
        alerts.emit("role.changed", key=("pre", i), summary="x")
    for n_ in names:
        for _ in range(alerts.BURST_THRESHOLD):
            alerts.note_login_failure("198.51.100.4", n_)
    bursts = sum(1 for _, e in env.times if e == "auth.login_failed_burst")
    check("with the open slots already used, only 5 reserved slots go to staff-subject bursts", bursts == use, str(bursts))
    env.close()
    env = Env()
    alerts.set_staff(ids=(), names=["boss"])
    for _ in range(alerts.BURST_THRESHOLD):
        alerts.note_login_failure("198.51.100.3", "boss")
    check("a single burst against a staff account is still sent",
          sum(1 for _, e in env.times if e == "auth.login_failed_burst") == 1)
    env.close()

    # --- update.available once per version, also for overlapping checks
    env = Env(slow_settings=True)
    data = {"portal": {"update_available": True, "latest": "9.9.9", "current": "1.0.0"},
            "mediamtx": {"update_available": False}}
    sent = await asyncio.gather(alerts.note_updates(data), alerts.note_updates(data))
    await env.settle()
    check("two overlapping checks send one update alert in all", sum(sent) == 1, str(sent))
    check("and one alert reached the hook", env.fired.count("update.available") == 1, str(env.fired))
    again = await alerts.note_updates(data)
    check("a later check of the same version sends nothing", again == 0)
    data["portal"]["latest"] = "9.9.10"
    check("a newer version is announced", await alerts.note_updates(data) == 1)
    env.close()

    # --- a notice that a paused hook refused is not lost: counts kept, sent again when the pause ends
    env = Env(virtual=True)
    alerts.note_dropped("role.changed")
    alerts.note_dropped("role.changed")
    await env.advance(1000.0 + alerts.NOTICE_DELAY + 1)
    notices = [p for _, e, p in env.payloads if e == "alerts.suppressed"]
    check("the first notice names the two dropped alerts", len(notices) == 1 and "role.changed: 2" in notices[0]["summary"])
    alerts.note_dropped("alerts.suppressed", 100.0)
    alerts.note_dropped("alerts.suppressed", 100.0)     # a second hook refusing the same notice
    check("the refused notice's counts are kept", alerts._held == {"role.changed": 2}, str(alerts._held))
    await env.pump()
    check("one retry is pending, not two", alerts._notice_scheduled and len([1 for _, f in env.timers if not f.done()]) == 1,
          str(env.timers))
    await env.advance(env.t + 50)
    check("nothing is sent before the pause ends",
          len([1 for _, e, _p in env.payloads if e == "alerts.suppressed"]) == 1)
    await env.advance(env.t + 100)
    notices = [p for _, e, p in env.payloads if e == "alerts.suppressed"]
    check("the notice is sent again after the pause with the same counts",
          len(notices) == 2 and "role.changed: 2" in notices[1]["summary"], str([n["summary"] for n in notices]))
    check("and the counts are then cleared", alerts.suppressed_count() == 0)
    for _ in range(alerts.NOTICE_RETRY_MAX + 3):
        alerts.note_dropped("alerts.suppressed", 40.0)
        await env.advance(env.t + 50)
    before = len([1 for _, e, _p in env.payloads if e == "alerts.suppressed"])
    await env.advance(env.t + alerts.NOTICE_RETRY_LIMIT * 3)
    check("a hook that refuses every time is retried a bounded number of times, then the counts are dropped",
          len([1 for _, e, _p in env.payloads if e == "alerts.suppressed"]) == before
          and alerts.suppressed_count() == 0 and before <= 2 + alerts.NOTICE_RETRY_MAX + 1, str(before))
    env.close()

    # giving up on a notice drops only its own counts, never those held back since
    env = Env(virtual=True)
    alerts._notice_retries = alerts.NOTICE_RETRY_MAX
    alerts._last_notice = (alerts._notice_gen, {"role.changed": 2}, {"role.changed": {alerts.WHY_SLOW}})
    alerts._held["moderation.action"] = 3
    alerts._held_why["moderation.action"] = {alerts.WHY_GLOBAL}
    alerts.note_dropped("alerts.suppressed", 10.0)
    check("giving up on a refused notice keeps the counts held back since, and does not add its own back",
          alerts._held == {"moderation.action": 3} and alerts._notice_retries == 0, str(alerts._held))
    env.close()


asyncio.run(main())
if failures:
    print(f"\ntest_alert_limits: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_alert_limits: all checks passed")
