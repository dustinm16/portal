"""The "alerts held back" notice names the reason an alert was dropped for a hook: a hook's own rate limit
reads "rate limit of the hook", a receiver that answered 429 still reads "receiver asked to slow down", and a
notice that mixes the two names each against its kind. A fake clock and fake delivery; nothing is sent.

Run: venv/bin/python tests/test_alert_rate_reason.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

import alerts  # noqa: E402

failures = []
DEADLINE = 30


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


class Env:
    def __init__(self):
        self.t = 1000.0
        self.payloads = []
        self.timers = []
        alerts.reset_state()
        alerts._clock = lambda: self.t

        async def virtual_sleep(seconds):
            fut = asyncio.get_running_loop().create_future()
            self.timers.append((self.t + seconds, fut))
            await fut
        alerts._sleep = virtual_sleep

        async def fire(event, payload):
            self.payloads.append((event, payload))
            return 1

        async def get(key):
            return None

        async def put(key, value):
            return None
        alerts.bind(fire=fire, notify=None, get_setting=get, set_setting=put)
        alerts.bind_record(None)

    async def pump(self):
        for _ in range(8):
            await asyncio.sleep(0)

    async def run_timers(self):
        await self.pump()
        for _, fut in list(self.timers):
            if not fut.done():
                fut.set_result(None)
        await self.pump()

    def notices(self):
        return [p for e, p in self.payloads if e == "alerts.suppressed"]


async def main():
    env = Env()
    alerts.note_dropped("role.changed", 5.0, alerts.WHY_RATE)
    alerts.note_dropped("role.changed", 5.0, alerts.WHY_RATE)
    await env.run_timers()
    got = env.notices()
    text = got[0]["summary"] if got else ""
    check("a notice was sent for the rate-limit drops", len(got) == 1, str(env.payloads))
    check("it counts the two drops", "role.changed: 2" in text, text)
    check("it names the hook's rate limit", "rate limit" in text and "hook" in text, text)
    check("it does not say the receiver asked to slow down", "slow down" not in text, text)

    env = Env()
    alerts.note_dropped("role.changed", 5.0)
    await env.run_timers()
    text = env.notices()[0]["summary"] if env.notices() else ""
    check("(control) a drop for a paused receiver still says it asked to slow down", "slow down" in text, text)

    env = Env()
    alerts.note_dropped("role.changed", 5.0, alerts.WHY_RATE)
    alerts.note_dropped("moderation.action", 5.0)
    await env.run_timers()
    text = env.notices()[0]["summary"] if env.notices() else ""
    check("a notice mixing both reasons labels each kind",
          "role.changed: 1 (rate limit of the hook)" in text and "moderation.action: 1 (receiver asked to slow down)" in text, text)

    env = Env()
    before = dict(alerts._held)
    alerts.note_dropped("alerts.suppressed", 100.0)
    check("(control) a refused notice is still never counted as an alert", alerts._held == before, str(alerts._held))


try:
    asyncio.run(asyncio.wait_for(main(), DEADLINE))
except asyncio.TimeoutError:
    check("finished within its deadline", False, f"{DEADLINE} s")
if failures:
    print(f"\ntest_alert_rate_reason: {len(failures)} FAILED")
    sys.exit(1)
print("\ntest_alert_rate_reason: all checks passed")
