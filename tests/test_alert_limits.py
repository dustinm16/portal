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
    def __init__(self, slow_settings=False):
        self.t = 1000.0
        self.fired = []
        self.times = []          # (time, event) of every delivery, recorded synchronously
        self.settings = {}
        self.slow = slow_settings
        alerts.reset_state()
        alerts._clock = lambda: self.t

        async def quick_sleep(_seconds):
            await asyncio.sleep(0)

        alerts._sleep = quick_sleep
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
        return 1

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

    # --- the notice is counted and sent once per trip
    env = Env()
    rng = random.Random(7)
    t = 0.0
    n = 0
    while t < 6000:
        t += rng.expovariate(1 / 5.0)
        env.t = 1000.0 + t
        n += 1
        alerts.emit("role.changed", key=f"k{n}", summary="x")
    await env.settle()
    notices = [t for t, e in env.times if e == "alerts.suppressed"]
    regular = [(t, e) for t, e in env.times if e != "alerts.suppressed"]
    check("under sustained load there is one notice for the one trip", len(notices) == 1, str(len(notices)))
    check("no window holds more than CAP_ALERTS regular alerts",
          worst_window(regular, alerts.CAP_WINDOW) <= alerts.CAP_ALERTS, str(worst_window(regular, alerts.CAP_WINDOW)))
    check("no window holds more than CAP_ALERTS plus the notice in all",
          worst_window(env.times, alerts.CAP_WINDOW) <= alerts.CAP_ALERTS + 1,
          str(worst_window(env.times, alerts.CAP_WINDOW)))
    await env.settle()
    env.close()

    env = Env()
    for i in range(alerts.CAP_ALERTS + 3):
        alerts.emit("role.changed", key=i, summary="x")
    env.t += alerts.CAP_WINDOW / 2
    alerts.emit("role.changed", key="mid", summary="x")
    env.t += alerts.CAP_WINDOW * 0.6
    for i in range(alerts.CAP_ALERTS + 3):
        alerts.emit("role.changed", key=f"b{i}", summary="x")
    await env.settle()
    check("a refusal inside the window does not end the trip, so no second notice yet",
          sum(1 for _, e in env.times if e == "alerts.suppressed") == 1)
    env.t += alerts.CAP_WINDOW + 5
    for i in range(alerts.CAP_ALERTS + 3):
        alerts.emit("role.changed", key=f"c{i}", summary="x")
    await env.settle()
    check("a quiet window ends the trip, and the next trip sends its own notice",
          sum(1 for _, e in env.times if e == "alerts.suppressed") == 2)
    await env.settle()
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


asyncio.run(main())
if failures:
    print(f"\ntest_alert_limits: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_alert_limits: all checks passed")
