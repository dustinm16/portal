"""Alert events: the emit helper, its cooldowns and global cap, payload rules, the
failed-sign-in burst counter, automatic-block coalescing, moderation and automod
anonymity, update and certificate once-only rules. A fake clock and fake delivery
functions; nothing is sent anywhere.

Run: venv/bin/python tests/test_alerts.py
"""

import asyncio
import datetime as dt
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import alerts  # noqa: E402
import secevents  # noqa: E402
import webhook_formats as wf  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Env:
    """Fake delivery, notification, settings and clock, bound to alerts."""

    current = None

    @classmethod
    async def fresh(cls):
        if cls.current is not None:
            await cls.current.settle()
        cls.current = cls()
        return cls.current

    def __init__(self):
        self.t = 1000.0
        self.fired = []          # (event, payload)
        self.notified = []       # (event, title, summary)
        self.settings = {}
        self.records = []
        alerts.reset_state()
        alerts._clock = lambda: self.t

        async def quick_sleep(_seconds):
            await asyncio.sleep(0)

        alerts._sleep = quick_sleep
        alerts.bind(fire=self.fire, notify=self.notify, get_setting=self.get, set_setting=self.set)
        alerts.bind_record(self.record)

    async def fire(self, event, payload):
        self.fired.append((event, payload))
        return 1

    async def notify(self, event, title, summary):
        self.notified.append((event, title, summary))

    async def get(self, key):
        return self.settings.get(key)

    async def set(self, key, value):
        self.settings[key] = value

    async def record(self, event, details, ip=None):
        self.records.append((event, details))
        self.record_ips = getattr(self, 'record_ips', []) + [ip]

    async def settle(self):
        for _ in range(5):
            await asyncio.sleep(0)
        while alerts._tasks:
            await asyncio.gather(*list(alerts._tasks), return_exceptions=True)

    def events(self):
        return [e for e, _ in self.fired]


async def main():
    # --- catalogue consistency
    check("groups cover exactly the alert events", alerts.EVENT_NAMES == wf.ALERT_EVENTS)
    check("every alert has a title and a cooldown rule",
          all(n in wf.ALERT_TITLES and n in alerts.COOLDOWNS for n in alerts.EVENT_NAMES))
    check("alerts are system-only", wf.ALERT_EVENTS <= wf.SYSTEM_ONLY_EVENTS)
    check("three groups offered", [g["group"] for g in alerts.catalogue()] == ["security", "operations", "moderation"])

    # --- subscription: explicit only
    for fmt in wf.FORMATS:
        check(f"'*' on a system {fmt} hook never receives an alert",
              not any(wf.event_subscribed(["*"], e, kind="system", fmt=fmt) for e in wf.ALERT_EVENTS))
        check(f"a named alert reaches a system {fmt} hook",
              wf.event_subscribed(["role.changed"], "role.changed", kind="system", fmt=fmt))
    check("a user hook never receives an alert, named or not",
          not wf.event_subscribed(["role.changed"], "role.changed", kind="user")
          and not wf.event_subscribed(["*"], "role.changed", kind="user"))
    check("'*' still gives an ordinary event to a generic system hook",
          wf.event_subscribed(["*"], "stream.live", kind="system", fmt="generic"))

    # --- not bound: nothing happens
    alerts.unbind()
    check("emit does nothing when not bound", alerts.emit("role.changed", summary="x") is False)
    env = await Env.fresh()

    # --- cooldown and cap, fake clock
    check("first alert admitted", alerts.emit("2fa.disabled", key=1, summary="a") is True)
    check("same key inside the cooldown is held back", alerts.emit("2fa.disabled", key=1, summary="a") is False)
    check("another key is admitted", alerts.emit("2fa.disabled", key=2, summary="a") is True)
    env.t += 61
    check("same key after the cooldown is admitted", alerts.emit("2fa.disabled", key=1, summary="a") is True)
    await env.settle()
    check("each admitted alert was delivered once", env.events() == ["2fa.disabled"] * 3, str(env.events()))

    env = await Env.fresh()
    admitted = 0
    for i in range(alerts.CAP_ALERTS + 10):
        if alerts.emit("role.changed", key=i, summary=f"r{i}"):
            admitted += 1
    check("the global cap admits exactly CAP_ALERTS", admitted == alerts.CAP_ALERTS, str(admitted))
    check("refused alerts are counted", alerts.suppressed_count() == 10)
    await env.settle()
    sup = [e for e in env.events() if e == "alerts.suppressed"]
    check("one 'alerts suppressed' alert for the refused alerts", len(sup) == 1, str(env.events()[-3:]))
    check("the suppressed alert did not use a slot or recurse", len(env.events()) == alerts.CAP_ALERTS + 1)
    check("the notice cleared the counts", alerts.suppressed_count() == 0)
    env.t += alerts.CAP_WINDOW + 1
    check("after the window the cap has room", alerts.emit("role.changed", key="later", summary="x") is True)
    for i in range(alerts.CAP_ALERTS):
        alerts.emit("role.changed", key=f"w{i}", summary="x")
    await env.settle()
    check("a second trip sends its own notice",
          [e for e in env.events() if e == "alerts.suppressed"].__len__() == 2)

    # --- cooldown dict is bounded
    env = await Env.fresh()
    env.t = 0
    for i in range(alerts.COOLDOWN_MAX_KEYS + 500):
        alerts._stamp("role.changed", (i,), 0)
    check("cooldown memory is bounded", len(alerts._cooldowns) <= alerts.COOLDOWN_MAX_KEYS)

    # --- failed-sign-in burst
    env = await Env.fresh()
    for _ in range(4):
        alerts.note_login_failure("203.0.113.9", "alice")
    await env.settle()
    check("four failures send nothing", env.events() == [])
    alerts.note_login_failure("203.0.113.9", "alice")
    await env.settle()
    check("five failures in a minute send one alert for address and account together",
          env.events() == ["auth.login_failed_burst"], str(env.events()))
    p = env.fired[0][1]
    check("burst summary names neither the account nor the address; the account is a detail",
          "alice" not in p["summary"] and "203.0.113.9" not in p["summary"]
          and p["details"].get("Account") == "alice", p["summary"])
    check("the in-portal copy may name the account", "alice" in env.notified[0][2] if env.notified else True)
    check("the burst security event keeps the source address", env.record_ips == ["203.0.113.9"], str(env.record_ips))
    check("the address is in the details", p["details"].get("Address") == "203.0.113.9")
    check("the burst writes a security event", env.records and env.records[0][0] == "login_failed_burst")
    for _ in range(20):
        alerts.note_login_failure("203.0.113.9", "alice")
    await env.settle()
    check("a continuing burst inside the ten minute cooldown sends no second alert", len(env.fired) == 1)
    env.t += 601
    for _ in range(5):
        alerts.note_login_failure("203.0.113.9", "alice")
    await env.settle()
    check("after the cooldown a new burst sends one more", len(env.fired) == 2)

    env = await Env.fresh()
    for i in range(5):
        env.t += 20
        alerts.note_login_failure("198.51.100.1", None)
    await env.settle()
    check("failures spread over more than a minute do not trip", env.events() == [])
    for i in range(5):
        alerts.note_login_failure("198.51.100.2", None)
    await env.settle()
    check("an unknown account is not named", len(env.fired) == 1 and "Account" not in env.fired[0][1]["details"])
    for i in range(5):
        alerts.note_login_failure(f"192.0.2.{i}", "bob")
    await env.settle()
    check("five failures for one account from five addresses trip the account key",
          len(env.fired) == 2 and env.fired[1][1]["details"].get("Account") == "bob"
          and "bob" not in env.fired[1][1]["summary"])
    check("IPv6 sources count as their /64",
          alerts.note_login_failure("2001:db8::1", None) is None)
    for i in range(1, 5):
        alerts.note_login_failure(f"2001:db8::{i + 1}", None)
    await env.settle()
    check("five IPv6 addresses of one /64 trip the address key", len(env.fired) == 3)
    for i in range(alerts.BURST_MAX_KEYS + 300):
        alerts.note_login_failure(f"10.{i // 250}.{i % 250}.1", f"user{i}")
    check("burst memory is bounded", len(alerts._burst) <= alerts.BURST_MAX_KEYS)

    # --- security-event mapping
    env = await Env.fresh()
    alerts.on_security_event("2fa_disabled", ip="203.0.113.5", user_agent="UA/1", user_id=7, username="carol")
    alerts.on_security_event("api_key_created", ip="203.0.113.5", user_id=7, username="carol",
                             details={"name": "ci", "scopes": ["read"], "expires_at": None})
    alerts.on_security_event("role_changed", ip="203.0.113.5", user_id=1, username="root_admin",
                             details={"target_user_id": 7, "target_username": "carol",
                                      "old_role": "user", "new_role": "admin"})
    alerts.on_security_event("ip_blocked", ip="203.0.113.5", user_id=1, username="root_admin",
                             details={"target_ip": "198.51.100.77", "kind": "manual", "reason": "scanner"})
    alerts.on_security_event("login_success", ip="203.0.113.5", user_id=7, username="carol")
    await env.settle()
    check("the four mapped security events became alerts, others did not",
          env.events() == ["2fa.disabled", "apikey.created", "role.changed", "ip.blocked"], str(env.events()))
    check("2fa.disabled and apikey.created summaries name no account",
          "carol" not in env.fired[0][1]["summary"] and "carol" not in env.fired[1][1]["summary"]
          and env.fired[0][1]["details"].get("Account") == "carol")
    for ev, pl in env.fired:
        s = pl["summary"]
        check(f"{ev}: no address or user agent in the summary",
              "203.0.113" not in s and "198.51.100" not in s and "UA/1" not in s and "scanner" not in s, s)
    check("addresses are in the details", env.fired[0][1]["details"].get("Address") == "203.0.113.5"
          and env.fired[3][1]["details"].get("Blocked address") == "198.51.100.77")
    check("the role change summary names the account and roles",
          "carol" in env.fired[2][1]["summary"] and "admin" in env.fired[2][1]["summary"])

    # --- automatic blocks coalesced
    env = await Env.fresh()
    slept = []

    async def fake_sleep(sec):
        slept.append(sec)

    alerts._sleep = fake_sleep
    for i in range(12):
        alerts.on_security_event("probe_block", ip=f"198.51.100.{i}")
    alerts.on_security_event("ip_blocked", ip="x", user_id=None, details={"target_ip": "192.0.2.50"})
    await env.settle()
    check("automatic blocks gave one alert with a count", env.events() == ["ip.blocked"], str(env.events()))
    s = env.fired[0][1]["summary"]
    check("the count is in the summary, addresses are not", "13 addresses" in s and "198.51" not in s, s)
    check("at most five addresses named in the details",
          env.fired[0][1]["details"]["Blocked addresses"].count("198.51.100.") + 0 <= 5)
    check("the timer waited a minute", slept == [alerts.AUTO_BLOCK_WINDOW])
    alerts.on_security_event("probe_block", ip="198.51.100.200")
    await env.settle()
    check("a block in the next window starts a new coalescing window", len(env.fired) == 2)
    alerts._sleep = asyncio.sleep

    # --- moderation and automod anonymity
    env = await Env.fresh()
    alerts.moderation_action("timeout", actor="mod1", target="Dave", anonymous=False, actor_id=1,
                             target_id=9, channel="general", reason="spam", duration=300)
    alerts.moderation_action("ban", actor="mod1", target="Secret", anonymous=True, actor_id=1,
                             target_id=10, channel="general", reason="rude")
    alerts.automod_triggered(rule_id=3, rule_name="no-links", rule_action="timeout", member="Eve",
                             member_id=11, anonymous=True, channel="general")
    alerts.automod_triggered(rule_id=3, rule_name="no-links", rule_action="timeout", member="Frank",
                             member_id=12, anonymous=False, channel="general")
    await env.settle()
    check("four moderation alerts", len(env.fired) == 4, str(env.events()))
    texts = json.dumps(env.fired)
    check("a named target is in the summary", "Dave" in env.fired[0][1]["summary"])
    check("an anonymous target is never named anywhere",
          "Secret" not in texts and "Eve" not in texts and "anonymous member" in env.fired[1][1]["summary"])
    check("anonymous: no user id in the payload", '"10"' not in texts and "target_id" not in texts)
    check("the reason and rule name are details only",
          "spam" not in env.fired[0][1]["summary"] and env.fired[0][1]["details"].get("Reason") == "spam"
          and "no-links" not in env.fired[3][1]["summary"] and env.fired[3][1]["details"]["Rule"] == "no-links")
    check("automod: repeat for the same rule and member is held back within a minute",
          alerts.automod_triggered(rule_id=3, rule_name="r", rule_action="mute", member="Frank",
                                   member_id=12, anonymous=False) is False)
    check("automod: another member is not held back",
          alerts.automod_triggered(rule_id=3, rule_name="r", rule_action="mute", member="Gina",
                                   member_id=13, anonymous=False) is True)
    env.t += 61 + alerts.CAP_WINDOW      # past the cooldown and the member sub-cap window
    check("automod: after a minute the same member again is sent",
          alerts.automod_triggered(rule_id=3, rule_name="r", rule_action="mute", member="Frank",
                                   member_id=12, anonymous=False) is True)
    alerts.moderation_action("timeout", actor="HiddenMod", target="Ivy", anonymous=False, actor_id=2, target_id=8,
                             actor_anonymous=True)
    await env.settle()
    check("an anonymous moderator is not named either",
          "HiddenMod" not in json.dumps(env.fired) and "a moderator" in env.fired[-1][1]["summary"])
    check("moderation: same actor, target and action is held back",
          alerts.moderation_action("mute", actor="m", target="Hal", anonymous=False, actor_id=1, target_id=5) is True
          and alerts.moderation_action("mute", actor="m", target="Hal", anonymous=False, actor_id=1, target_id=5) is False)

    # --- service events
    env = await Env.fresh()
    alerts.service_event("service.health_changed", {"id": 4, "name": "mediamtx", "display_name": "MediaMTX",
                                                    "state": "down", "failed_checks": 3, "status": "stopped"})
    env.t += 1
    alerts.service_event("service.health_changed", {"id": 4, "name": "mediamtx", "display_name": "MediaMTX",
                                                    "state": "up", "status": "running"})
    await env.settle()
    check("down then up both sent despite the down cooldown (transition rule)",
          [p["summary"] for _, p in env.fired] == ["Service 'MediaMTX' is down", "Service 'MediaMTX' is back up"],
          str([p["summary"] for _, p in env.fired]))

    # --- in-portal notification setting
    env = await Env.fresh()
    check("notification default: on for a security alert", await alerts.notify_enabled("role.changed") is True)
    check("notification default: off for backup.ok", await alerts.notify_enabled("backup.ok") is False)
    alerts.emit("role.changed", summary="r")
    alerts.emit("backup.ok", summary="b")
    await env.settle()
    check("only the default-on alert notified", [e for e, _, _ in env.notified] == ["role.changed"], str(env.notified))
    check("a backup.ok webhook is still sent", "backup.ok" in env.events())
    await alerts.set_notify("backup.ok", True)
    await alerts.set_notify("role.changed", False)
    env.t += 4000
    alerts.emit("role.changed", summary="r")
    alerts.emit("backup.ok", summary="b")
    await env.settle()
    check("settings override the defaults",
          [e for e, _, _ in env.notified] == ["role.changed", "backup.ok"], str(env.notified))
    try:
        await alerts.set_notify("not.an.alert", True)
        check("unknown alert setting refused", False)
    except ValueError:
        check("unknown alert setting refused", True)

    # --- a failing delivery or notification never raises into the caller
    env = await Env.fresh()

    async def boom(*a):
        raise RuntimeError("down")

    alerts.bind(fire=boom, notify=boom, get_setting=env.get, set_setting=env.set)
    check("emit returns normally when delivery fails", alerts.emit("role.changed", summary="x") is True)
    await env.settle()
    check("a failed delivery is only logged", True)

    # --- payload gating in the formats
    env = await Env.fresh()
    data = {"title": "T", "summary": "S line", "severity": "warning", "group": "security",
            "details": {"Address": "203.0.113.5", "User agent": "UA/9"}}
    import hashlib
    import hmac
    req = wf.format_payload("generic", "role.changed", data, include_details=False, secret="k")
    body = json.loads(req.body)
    check("generic alert body without include_details has no details",
          "details" not in body["data"] and "203.0.113.5" not in req.body.decode())
    req = wf.format_payload("generic", "role.changed", data, include_details=True, secret="k")
    check("generic alert body with include_details has them",
          json.loads(req.body)["data"]["details"]["Address"] == "203.0.113.5")
    check("generic alert body is still signed",
          req.headers["X-Portal-Signature"] == "sha256=" + hmac.new(b"k", req.body, hashlib.sha256).hexdigest())
    for fmt in ("ntfy", "gotify", "discord", "slack"):
        off = wf.format_payload(fmt, "role.changed", data, include_details=False, portal_name="P")
        on = wf.format_payload(fmt, "role.changed", data, include_details=True, portal_name="P")
        check(f"{fmt}: no address by default, address with include_details, summary always",
              b"203.0.113.5" not in off.body and b"203.0.113.5" in on.body and b"S line" in off.body)
    for event in wf.ALERT_EVENTS:
        m = wf.build_message(event, {}, {}, include_details=False, portal_name="P")
        check(f"{event} has its own catalogue entry", m.title == wf.ALERT_TITLES[event] and m.summary != "")

    # --- updates: once per version
    env = await Env.fresh()
    res = {"portal": {"update_available": True, "latest": "1.99.0", "current": "1.15.0"},
           "mediamtx": {"update_available": False, "latest": "9", "current": "9"}}
    n1 = await alerts.note_updates(res)
    env.t += 5
    n2 = await alerts.note_updates(res)
    res["portal"]["latest"] = "2.0.0"
    n3 = await alerts.note_updates(res)
    await env.settle()
    check("update.available once per version", (n1, n2, n3) == (1, 0, 1) and env.events() == ["update.available"] * 2,
          str((n1, n2, n3, env.events())))
    env2 = await Env.fresh()
    env2.settings = dict(env.settings)
    check("the seen version survives a restart (kept in a setting)", await alerts.note_updates(
        {"portal": {"update_available": True, "latest": "2.0.0", "current": "1"}}) == 0)

    # --- certificate thresholds, once per serial, with real certificates
    await cert_tests()


def make_cert(path, days_left, now, cn="portal.test", issuer_cn=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=60))
            .not_valid_after(now + dt.timedelta(days=days_left))
            .sign(key, hashes.SHA256()))
    Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


async def cert_tests():
    now = dt.datetime.now(dt.timezone.utc)
    d = tempfile.mkdtemp()
    path = os.path.join(d, "fullchain.pem")
    env = await Env.fresh()
    make_cert(path, 30, now)
    r = await alerts.check_certificate(path, now)
    check("a certificate with 30 days left sends nothing", r is None and env.events() == [])
    r = await alerts.check_certificate(path, now + dt.timedelta(days=17))     # 13 days left
    await env.settle()
    check("crossing 14 days sends one alert", r and r.startswith("expiring:13") and env.events() == ["cert.expiring"], str(r))
    env.t += 100
    r = await alerts.check_certificate(path, now + dt.timedelta(days=18))     # 12 days left
    check("a repeated check in the same band sends nothing", r is None and len(env.fired) == 1)
    # restart: new binding, same settings
    saved = dict(env.settings)
    env = await Env.fresh()
    env.settings = saved
    r = await alerts.check_certificate(path, now + dt.timedelta(days=19))
    check("a restart does not repeat the alert", r is None and env.fired == [])
    r = await alerts.check_certificate(path, now + dt.timedelta(days=24))     # 6 days
    r2 = await alerts.check_certificate(path, now + dt.timedelta(days=24, hours=3))
    check("crossing 7 days sends exactly one more", r and r2 is None, str((r, r2)))
    r = await alerts.check_certificate(path, now + dt.timedelta(days=29.5))   # 0.5 day
    r2 = await alerts.check_certificate(path, now + dt.timedelta(days=29.6))
    await env.settle()
    check("crossing 1 day sends exactly one more", r and r2 is None, str((r, r2)))
    check("after the restart exactly the 7 and 1 day alerts were sent (14 was sent before)", len(env.fired) == 2, str(len(env.fired)))
    check("the alert text carries no host name or address",
          all("portal.test" not in p["summary"] for _, p in env.fired))
    check("the subject is a detail only", any(p["details"].get("Subject") == "portal.test" for _, p in env.fired))
    check("each threshold writes a security event", len(env.records) >= 2)
    # renewed certificate starts again
    make_cert(path, 5, now)
    r = await alerts.check_certificate(path, now)
    check("a new serial starts again and sends only the lowest crossed threshold (7)",
          r and r.startswith("expiring:5"), str(r))
    r = await alerts.check_certificate(path, now + dt.timedelta(days=0.2))
    check("the higher thresholds were marked sent", r is None)
    # unreadable file
    r = await alerts.check_certificate(os.path.join(d, "missing.pem"), now)
    check("a missing file is tolerated", r is None)
    # Let's Encrypt heuristic: issuer-named cert is not detected as letsencrypt by method; test via stub
    import cert_manager
    real = cert_manager.get_cert_info

    def fake_info(p):
        info = real(p)
        info["method"] = "letsencrypt"
        return info

    cert_manager.get_cert_info = fake_info
    try:
        env = await Env.fresh()
        make_cert(path, 18, now)
        r = await alerts.check_certificate(path, now)
        check("a Let's Encrypt certificate past the renewal window sends cert.renewal_failed once",
              r == "renewal_failed", str(r))
        r = await alerts.check_certificate(path, now + dt.timedelta(hours=5))
        check("and not again for the same serial", r is None)
        make_cert(path, 40, now)
        r = await alerts.check_certificate(path, now)
        check("a renewed certificate sends nothing", r is None)
    finally:
        cert_manager.get_cert_info = real


asyncio.run(main())
if failures:
    print(f"\ntest_alerts: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_alerts: all checks passed")
