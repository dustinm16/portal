"""Sign-in and registration hardening: an unknown account costs the same password hash as a real one,
and a refused registration never writes the typed name to the journal.

Run:  venv/bin/python tests/test_auth_hardening.py
"""

import asyncio
import contextlib
import io
import logging
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import aiohttp  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

import auth  # noqa: E402
import server  # noqa: E402
from auth import create_user  # noqa: E402
from config import Config  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


# ---------------------------------------------------------------------------
# Unknown account: the password hash runs anyway (counted, not timed)
# ---------------------------------------------------------------------------

class _FakeDB:
    def __init__(self, users):
        self.users = users

    async def get_user_by_username(self, name):
        return self.users.get(name)


DUMMY = getattr(auth, "_DUMMY_PASSWORD_HASH", None)


async def timing_unit():
    real_db, real_verify = auth.db, auth.verify_password
    calls = []

    def counting(password, password_hash):
        calls.append(password_hash)
        return real_verify(password, password_hash)

    known_hash = auth.hash_password("Right-pass-1234!")
    auth.db = _FakeDB({"real": {"id": 1, "username": "real", "password_hash": known_hash}})
    auth.verify_password = counting
    try:
        user, why = await auth.authenticate_user_reason("nobody", "Whatever-pass-1")
        check("an unknown account is refused as unknown_user", user is None and why == "unknown_user")
        check("...after one password verification, against the fixed dummy hash",
              calls == [DUMMY], str(calls))
        calls.clear()
        user, why = await auth.authenticate_user_reason("real", "Wrong-pass-1234!")
        check("a real account with a wrong password: one verification, bad_password",
              why == "bad_password" and len(calls) == 1 and calls[0] == known_hash)
        calls.clear()
        user, why = await auth.authenticate_user_reason("real", "Right-pass-1234!")
        check("a real account with the right password: one verification, signed in",
              user and why is None and len(calls) == 1)
        calls.clear()
        for typed in (12345, None, ["x"], b"bytes-password"):
            user, why = await auth.authenticate_user_reason("nobody", typed)
            check(f"an unknown account with a {type(typed).__name__} password is still unknown_user, never an error",
                  user is None and why == "unknown_user")
        check("every one of those ran the dummy verification", len(calls) == 4 and set(calls) == {DUMMY})
    finally:
        auth.db, auth.verify_password = real_db, real_verify
    check("the dummy hash is a real Argon2 hash made at import, and never matches a typed password",
          bool(DUMMY) and DUMMY.startswith("$argon2") and not real_verify("anything", DUMMY))
    src = Path(auth.__file__).read_text()
    i = src.index("async def authenticate_user_reason")
    check("there is no other early return for a missing account in the sign-in function",
          src[i:src.index("async def authenticate_user(", i)].count('return None, "unknown_user"') == 1)


# ---------------------------------------------------------------------------
# Registration: refusal paths do not log the typed name
# ---------------------------------------------------------------------------

class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.INFO)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


async def registration_unit(tmp):
    server.db.db_path = str(Path(tmp) / "t.db")
    await server.db.connect()
    sa = await create_user("sa_reg", "Sa-pass-12345!", is_admin=True)
    await server.db.set_user_role(sa["id"], "superadmin")
    await create_user("existing_reg", "Existing-pass-123!", is_admin=False)
    Config.RATE_LIMIT_REQUESTS = 100000
    Config.SESSION_COOKIE_SECURE = False
    server.rate_limits.clear()
    srv = TestServer(server.create_app(), host="127.0.0.1")
    await srv.start_server()
    base = f"http://127.0.0.1:{srv.port}"
    cap = _Capture()
    logging.getLogger().addHandler(cap)
    old_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.INFO)
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as admin:
            async with admin.post(base + "/login", json={"username": "sa_reg", "password": "Sa-pass-12345!"}) as r:
                await r.read()
            codes = []
            for _ in range(2):
                async with admin.post(base + "/api/admin/invite-codes", json={"type": "single_use"}) as r:
                    codes.append((await r.json())["code"])

        async def register(name, code):
            out = io.StringIO()
            start = len(cap.lines)
            with contextlib.redirect_stdout(out):
                async with aiohttp.ClientSession() as s:
                    async with s.post(base + "/api/register", json={
                            "username": name, "password": "Reg-pass-12345!", "invite_code": code}) as r:
                        await r.read()
                        status = r.status
            return status, "\n".join(cap.lines[start:]) + "\n" + out.getvalue()

        typed = {"bad": "TypedBadInvite77", "dup": "existing_reg", "ok": "TypedWelcome77", "limit": "TypedLimited77"}
        st, text = await register(typed["bad"], "bad-bad-code")
        check("a refused registration (invalid invite) is a 403", st == 403)
        check("...and its journal lines (log and stdout) do not hold the typed name", typed["bad"] not in text and "FAILED" in text
              and "an unknown account" in text, text)
        st, text = await register(typed["dup"], codes[0])
        check("a registration that fails while creating the account is a 400", st == 400, str(st))
        check("...and does not log the typed name either", typed["dup"] not in text, text)
        st, text = await register(typed["ok"], codes[1])
        check("a successful registration is a 201", st == 201, str(st))
        check("...and logs the new account's name, in the usage line and in the registered line",
              f"user={typed['ok']} status=SUCCESS" in text and f"User '{typed['ok']}' registered" in text, text)
        st, text = await register(typed["limit"], "any-code")
        check("a second registration from the same address in 24 hours is refused with 429", st == 429, str(st))
        check("...and its rate-limit line does not hold the typed name", typed["limit"] not in text
              and "Registration rate limit" in text and "an unknown account" in text, text)
    finally:
        logging.getLogger().removeHandler(cap)
        logging.getLogger().setLevel(old_level)
        await srv.close()
        await server.db.close()


def main():
    try:
        asyncio.run(timing_unit())
    except Exception as e:
        check("the sign-in unit ran to the end", False, f"{type(e).__name__}: {e}")
    with tempfile.TemporaryDirectory() as tmp:
        try:
            asyncio.run(registration_unit(tmp))
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    print(f"\n{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
