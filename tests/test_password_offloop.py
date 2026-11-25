"""Password hashing and checking run off the event loop (1.24.2).

Sign-in, registration, password change, 2FA disable and the admin password reset no longer run Argon2 on the
loop: a burst of sign-ins must not stall streaming hooks and chat. The work goes through auth.hash_password_async
and auth.verify_password_async, which run the hash in a worker thread under a semaphore of
auth.PASSWORD_HASH_WORKERS. Slow hashes are faked with a sleep, so the timing is deterministic.

Run: venv/bin/python tests/test_password_offloop.py   (90 second deadline)
"""

import asyncio
import re
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

import auth  # noqa: E402
import server  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SLOW = 0.3


class _FakeDB:
    def __init__(self, users):
        self.users = users

    async def get_user_by_username(self, name):
        return self.users.get(name)


async def max_gap_while(coro):
    """Run coro while a task ticks every 10 ms; return (result, longest gap between ticks)."""
    gaps = []
    stop = False

    async def ticker():
        last = time.monotonic()
        while not stop:
            await asyncio.sleep(0.01)
            now = time.monotonic()
            gaps.append(now - last)
            last = now
    t = asyncio.create_task(ticker())
    await asyncio.sleep(0.05)
    try:
        res = await coro
    finally:
        stop = True
        await t
    return res, max(gaps)


async def unit():
    real_db, real_verify, real_hash = auth.db, auth.verify_password, auth.hash_password
    active = 0
    peak = 0
    lock = threading.Lock()
    threads = []

    def slow_verify(password, password_hash):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            threads.append(threading.current_thread())
        time.sleep(SLOW)
        with lock:
            active -= 1
        return password == "right"

    known = real_hash("right")
    auth.db = _FakeDB({"real": {"id": 1, "username": "real", "password_hash": known}})
    auth.verify_password = slow_verify
    try:
        (res, gap) = await max_gap_while(auth.authenticate_user_reason("real", "right"))
        check("a sign-in whose hash takes 300 ms does not stall a ticking loop task", gap < SLOW / 2, f"gap {gap:.3f}s")
        check("... and still signs the right password in", res[0] is not None and res[1] is None)
        check("... the hash ran in a worker thread", threads and threads[-1] is not threading.main_thread())

        t0 = time.monotonic()
        await auth.authenticate_user_reason("nobody", "right")
        t_unknown = time.monotonic() - t0
        t0 = time.monotonic()
        user, why = await auth.authenticate_user_reason("real", "wrong")
        t_wrong = time.monotonic() - t0
        check("a wrong password is bad_password", user is None and why == "bad_password")
        check("a wrong user and a wrong password take the same time (one hash each)",
              abs(t_unknown - t_wrong) < 0.1 and t_unknown >= SLOW * 0.9 and t_wrong >= SLOW * 0.9,
              f"{t_unknown:.3f} vs {t_wrong:.3f}")

        peak = 0
        res = await asyncio.gather(*[auth.verify_password_async("right", known) for _ in range(12)])
        check("12 concurrent checks all answer", res == [True] * 12)
        check("... never more than PASSWORD_HASH_WORKERS at once, and really in parallel",
              1 < peak <= auth.PASSWORD_HASH_WORKERS, f"peak {peak} cap {auth.PASSWORD_HASH_WORKERS}")
        check("the bound is 4", auth.PASSWORD_HASH_WORKERS == 4)
    finally:
        auth.db, auth.verify_password = real_db, real_verify

    # hashing: same bound, off the loop
    seen = []

    def slow_hash(password):
        seen.append(threading.current_thread())
        time.sleep(SLOW)
        return real_hash(password)
    auth.hash_password = slow_hash
    try:
        (res, gap) = await max_gap_while(auth.hash_password_async("Some-password-1"))
        check("hashing a new password does not stall the loop", gap < SLOW / 2, f"gap {gap:.3f}s")
        check("... the hash ran in a worker thread and verifies", seen and seen[0] is not threading.main_thread()
              and real_verify("Some-password-1", res))
    finally:
        auth.hash_password = real_hash


async def http():
    env = await h.boot(names=("owner", "bob"), superadmin=("owner",))
    base = env.base
    real_verify, real_hash = auth.verify_password, auth.hash_password
    main = threading.main_thread()
    where = []

    def v(password, password_hash):
        where.append(("verify", threading.current_thread() is main))
        return real_verify(password, password_hash)

    def hh(password):
        where.append(("hash", threading.current_thread() is main))
        return real_hash(password)
    auth.verify_password, auth.hash_password = v, hh
    try:
        import aiohttp
        async with aiohttp.ClientSession() as anon:
            async with anon.post(base + "/login", json={"username": "bob", "password": h.PW}) as r:
                await r.read()
                check("login still works", r.status == 200, str(r.status))
            async with anon.post(base + "/login", json={"username": "ghost", "password": "x" * 12}) as r:
                await r.read()
                check("login of an unknown name is still refused", r.status == 401, str(r.status))
        check("sign-in hashes ran off the loop thread", where and not any(m for _, m in where), str(where))
        where.clear()
        bob = env.sessions["bob"]
        async with bob.post(base + "/api/me/password", json={"current_password": h.PW, "new_password": "New-pass-123456!"}) as r:
            await r.read()
            check("password change answers 200", r.status == 200, str(r.status))
        kinds = [k for k, _ in where]
        check("password change checks the old and hashes the new password, off the loop",
              kinds == ["verify", "hash"] and not any(m for _, m in where), str(where))
        where.clear()
        owner = env.sessions["owner"]
        async with owner.post(base + f"/api/users/{env.uid['bob']}/reset-password", json={"new_password": "Reset-pass-123456!"}) as r:
            await r.read()
            check("admin password reset answers 200", r.status == 200, str(r.status))
        check("admin reset hashes off the loop", [k for k, _ in where] == ["hash"] and not any(m for _, m in where), str(where))
        where.clear()
        async with aiohttp.ClientSession() as anon:
            await auth.create_user("viaapi", "Created-pass-123456!")
        check("create_user hashes off the loop", [k for k, _ in where] == ["hash"] and not any(m for _, m in where), str(where))
    finally:
        auth.verify_password, auth.hash_password = real_verify, real_hash
    await h.shutdown(env)


def source_checks():
    src = (ROOT / "server.py").read_text()
    bare = re.findall(r"(?<![\w.])(?:verify_password|hash_password)\(", src)
    check("server.py has no synchronous password hash or check left in a handler", not bare, str(bare))
    a = (ROOT / "auth.py").read_text()
    i = a.index("async def authenticate_user_reason")
    body = a[i:a.index("async def authenticate_user(", i)]
    check("the dummy-hash equalisation call is kept, awaited", "await verify_password_async(password, _DUMMY_PASSWORD_HASH)" in body)


async def main():
    await unit()
    await http()
    source_checks()


asyncio.run(asyncio.wait_for(main(), 90))
h.finish("test_password_offloop")
