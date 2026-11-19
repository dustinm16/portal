"""Cloudflare ranges: a list refused by an automatic limit is held for approval, a reset during a
refresh wins, an approved list survives a restart, and the panel is told why a saved list is ignored.

Run:  venv/bin/python tests/test_cf_pending.py
      PORTAL_SRC=/path/to/other/tree venv/bin/python tests/test_cf_pending.py
"""

import asyncio
import ipaddress
import json
import os
import sys
import tempfile
from pathlib import Path

SRC = os.environ.get("PORTAL_SRC") or str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SRC)

_TMP = tempfile.TemporaryDirectory()
TEST_DB = str(Path(_TMP.name) / "cfp.db")
os.environ["DATABASE_PATH"] = TEST_DB
os.environ.setdefault("JWT_SECRET", "x" * 64)

import ipguard  # noqa: E402
import secevents  # noqa: E402
import server  # noqa: E402
from database import Database  # noqa: E402

failures = []


class section:
    """A group of checks that records a FAIL (and carries on) when it raises, so a missing name
    on an older tree fails that group instead of stopping the whole file."""

    def __init__(self, name):
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        if value is not None and isinstance(value, Exception):
            check(f"{self.name} ran to the end", False, f"{type(value).__name__}: {value}")
            return True
        return False


LIMIT = getattr(ipguard, "ListLimitError", type("NoListLimitError", (Exception,), {}))


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


BUILTIN = list(server._CLOUDFLARE_NETWORKS)
V4 = [n for n in BUILTIN if ":" not in n]
V6 = [n for n in BUILTIN if ":" in n]
TEXT6 = "\n".join(V6) + "\n"


def v4_text(extra=0, keep=None):
    base = V4 if keep is None else V4[:keep]
    return "\n".join(base + [f"45.{i}.0.0/16" for i in range(extra)]) + "\n"


NETS = lambda: [ipaddress.ip_network(n) for n in BUILTIN]  # noqa: E731


# ---------------------------------------------------------------------------
# ipguard: which refusals may be approved
# ---------------------------------------------------------------------------

def refusal(t4, t6, current=None):
    try:
        ipguard.validate_cf_lists(t4, t6, current)
    except LIMIT as e:
        return "limit", e
    except ipguard.ListError as e:
        return "hard", e
    return None, None


check("too many new ranges is a limit refusal (approvable) that carries the parsed list",
      refusal(v4_text(6), TEXT6)[0] == "limit" and len(refusal(v4_text(6), TEXT6)[1].networks) == len(BUILTIN) + 6)
check("dropping most built-in ranges is a limit refusal", refusal(v4_text(8, keep=7), TEXT6)[0] == "limit")
cur = [ipaddress.ip_network(n) for n in V4[:8] + V6] + [ipaddress.ip_network(f"45.{i}.0.0/16") for i in range(20)]
fetched = "\n".join(V4[:8] + [f"46.{i}.0.0/16" for i in range(5)]) + "\n"
check("dropping most current ranges is a limit refusal",
      "current" in str(refusal(fetched, TEXT6, cur)[1]) and refusal(fetched, TEXT6, cur)[0] == "limit")
for label, t4, t6 in (
        ("a private range", v4_text(1) + "10.0.0.0/16\n", TEXT6),
        ("a range broader than the built-in floor", v4_text(1) + "45.0.0.0/12\n", TEXT6),
        ("a range broader than /8", v4_text(1) + "64.0.0.0/7\n", TEXT6),
        ("too few IPv4 ranges", "\n".join(V4[:3]), TEXT6),
        ("too few IPv6 ranges", v4_text(), "\n".join(V6[:2])),
        ("a bad line", v4_text() + "hello\n", TEXT6)):
    check(f"{label} is a hard refusal (never approvable)", refusal(t4, t6)[0] == "hard")
big = "\n".join(f"45.{i}.{j}.0/24" for i in range(1, 3) for j in range(60)) + "\n"
check("more than 100 ranges in a family is a hard refusal", refusal(big, TEXT6)[0] == "hard")
check("a hard failure in the IPv6 list is reported before a limit failure in the IPv4 list",
      refusal(v4_text(9), TEXT6 + "2a00::/28\n")[0] == "hard")
check("a list that equals the current one passes the limits (nothing changes)",
      refusal(v4_text(8, keep=7), TEXT6, [ipaddress.ip_network(n) for n in V4[:7]]
              + [ipaddress.ip_network(f"45.{i}.0.0/16") for i in range(8)] + [ipaddress.ip_network(n) for n in V6]) == (None, None))
with section("the hard-rule helper"):
    check("validate_cf_hard accepts what the limits refuse, and still refuses a private range",
          len(ipguard.validate_cf_hard(v4_text(9), TEXT6)) == len(BUILTIN) + 9
          and refusal(v4_text(1) + "192.168.0.0/16\n", TEXT6)[0] == "hard")
with section("the list id helper"):
    check("the list id ignores order and duplicates",
          ipguard.cf_list_id(NETS()) == ipguard.cf_list_id(list(reversed(NETS())) + NETS()[:2])
          and ipguard.cf_list_id(NETS()) != ipguard.cf_list_id(NETS()[:-1]))


# ---------------------------------------------------------------------------
# Server: pending list, approval, dismissal, restart, reset race
# ---------------------------------------------------------------------------

async def events(d, where="event = 'cf_ranges_refreshed'"):
    cur_ = await d.conn.execute(f"SELECT * FROM security_events WHERE {where} ORDER BY id")
    return [dict(r) for r in await cur_.fetchall()]


async def main():
    d = Database(TEST_DB)
    await d.connect()
    server.db = d
    secevents.log.bind(d)
    try:
        server._apply_cloudflare_networks(NETS(), "built-in")
        await d.set_setting(server.CF_SETTING_ENABLED, "true")

        with section('a refused list is held, with the reason and the exact differ'):
            t4 = v4_text(8)
            st = await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            pend = json.loads(await d.get_setting(server.CF_SETTING_PENDING) or "null")
            check("a list with 8 new ranges is refused: the list in use is unchanged and the failure is recorded",
                  st["ok"] is False and "8 new IPv4" in st["message"] and server._cf_source == "built-in"
                  and not server._is_trusted_proxy("45.0.0.9"), str(st))
            check("...and held as a pending list with reason, fetch time and the exact added and removed ranges",
                  pend and "8 new IPv4" in pend["reason"] and pend["fetched_at"]
                  and pend["added"] == sorted(f"45.{i}.0.0/16" for i in range(8)) and pend["removed"] == []
                  and sorted(pend["v4"]) == sorted(V4 + [f"45.{i}.0.0/16" for i in range(8)]) and pend["v6"] == sorted(V6)
                  and pend["id"] == st.get("pending_id"), str(pend))
            check("the saved list is untouched by a refusal", await d.get_setting(server.CF_SETTING_LIST) is None)
            evs = await events(d)
            check("one failure event, marked as pending, with the list id",
                  len(evs) == 1 and evs[0]["result"] == "failed"
                  and json.loads(evs[0]["details"]).get("pending") is True
                  and json.loads(evs[0]["details"]).get("list_id") == pend["id"], str(evs))
            view = await server._cf_ranges_view()
            check("the view carries the pending list for the panel",
                  view["pending"] and view["pending"]["id"] == pend["id"] and view["pending"]["v4"] == len(V4) + 8
                  and view["pending"]["added"] == pend["added"] and view["pending"]["diff_is_current"] is True
                  and "8 new" in view["pending"]["reason"], str(view["pending"]))

        with section('the same list fetched again'):
            for _ in range(3):
                await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            check("fetching the same refused list again writes no new failure event", len(await events(d)) == 1)
            check("...and keeps the one pending list", json.loads(await d.get_setting(server.CF_SETTING_PENDING))["id"] == pend["id"])
            await server.refresh_cloudflare_ranges(texts=(v4_text(9), TEXT6))
            check("a different refused list replaces the pending one and is one more event",
                  json.loads(await d.get_setting(server.CF_SETTING_PENDING))["id"] != pend["id"] and len(await events(d)) == 2)
            # back to the first one for the approval below
            await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            pend = json.loads(await d.get_setting(server.CF_SETTING_PENDING))
            check("(the first list is pending again, a third event)", len(await events(d)) == 3)

        with section('hard rules cannot be approved around'):
            good_row = await d.get_setting(server.CF_SETTING_PENDING)
            for label, mutate in (("a private range", lambda p: p["v4"].append("10.0.0.0/16")),
                                  ("a range broader than the floor", lambda p: p["v4"].append("45.0.0.0/12")),
                                  ("too few ranges", lambda p: p.update(v4=p["v4"][:3]))):
                bad = json.loads(good_row)
                mutate(bad)
                await d.set_setting(server.CF_SETTING_PENDING, json.dumps(bad))
                code, body = await server.approve_cloudflare_pending(bad["id"])
                check(f"approval re-checks the hard rules: {label} is refused", code == 400 and "cannot be overridden" in body["error"]
                      and server._cf_source == "built-in" and await d.get_setting(server.CF_SETTING_LIST) is None, str(body))
            await d.set_setting(server.CF_SETTING_PENDING, good_row)

            code, body = await server.approve_cloudflare_pending("0" * 16)
            check("approving a list id that is not the pending one is a 409 and changes nothing",
                  code == 409 and server._cf_source == "built-in")

        with section('approval'):
            code, body = await server.approve_cloudflare_pending(pend["id"])
            check("approval applies the list at once, with counts only in the result",
                  code == 200 and body == {"v4": len(V4) + 8, "v6": len(V6), "added": 8, "removed": 0}
                  and server._cf_source == "fetched" and server._is_trusted_proxy("45.3.0.9"), str(body))
            saved = json.loads(await d.get_setting(server.CF_SETTING_LIST))
            check("the approved list is saved with its approval flag; the pending list is gone",
                  saved["approved"] is True and len(saved["v4"]) == len(V4) + 8
                  and await d.get_setting(server.CF_SETTING_PENDING) is None)
            last = json.loads(await d.get_setting(server.CF_SETTING_LAST))
            check("the last result reads as a success", last["ok"] is True and last["v4"] == len(V4) + 8, str(last))
            code, _ = await server.approve_cloudflare_pending(pend["id"])
            check("approving again (nothing pending) is a 404", code == 404)

        with section('restart with the approved list'):
            server._apply_cloudflare_networks(NETS(), "built-in")
            await server._load_cloudflare_state()
            check("a restart loads the approved list although it adds more than 5 ranges",
                  server._cf_source == "fetched" and server._is_trusted_proxy("45.3.0.9"))
            # the same list without the flag is what the old code saved: the limits apply again at load
            plain = dict(saved)
            plain.pop("approved")
            await d.set_setting(server.CF_SETTING_LIST, json.dumps(plain))
            server._apply_cloudflare_networks(NETS(), "built-in")
            await server._load_cloudflare_state()
            check("(control) a list that only adds ranges is loaded with or without the flag", server._cf_source == "fetched")
            # an approved list that retired most built-in ranges survives a restart, an unflagged one does not
            retire = {"v4": V4[:7] + [f"45.{i}.0.0/16" for i in range(8)], "v6": V6, "fetched_at": "x", "approved": True}
            await d.set_setting(server.CF_SETTING_LIST, json.dumps(retire))
            server._apply_cloudflare_networks(NETS(), "built-in")
            await server._load_cloudflare_state()
            check("an approved list that retired 8 of 15 built-in ranges is loaded after a restart", server._cf_source == "fetched")
            retire.pop("approved")
            await d.set_setting(server.CF_SETTING_LIST, json.dumps(retire))
            server._apply_cloudflare_networks(NETS(), "built-in")
            await server._load_cloudflare_state()
            check("the same list without the flag is ignored at start (the automatic rules stay in force)",
                  server._cf_source == "built-in")
            hard_bad = {"v4": V4 + ["10.0.0.0/16"], "v6": V6, "fetched_at": "x", "approved": True}
            await d.set_setting(server.CF_SETTING_LIST, json.dumps(hard_bad))
            await server._load_cloudflare_state()
            check("a flagged list is still checked by the hard rules at start", server._cf_source == "built-in")

        with section('the next identical fetch after an approval is not held again'):
            await server.reset_cloudflare_ranges()
            await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            pend = json.loads(await d.get_setting(server.CF_SETTING_PENDING))
            code, _ = await server.approve_cloudflare_pending(pend["id"])
            before_events = len(await events(d))
            st = await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            check("after an approval the same published list is a success with nothing changed, not pending again",
                  st["ok"] and st["added"] == [] and st["removed"] == []
                  and await d.get_setting(server.CF_SETTING_PENDING) is None
                  and json.loads(await d.get_setting(server.CF_SETTING_LIST))["approved"] is True, str(st))
            check("...and still loads after a restart",
                  (server._apply_cloudflare_networks(NETS(), "built-in") or True)
                  and (await server._load_cloudflare_state() or True) and server._cf_source == "fetched")
            check("(that success is one ok event)", len(await events(d)) == before_events + 1
                  and (await events(d))[-1]["result"] == "ok")

        with section('a good refresh clears a pending list'):
            await server.reset_cloudflare_ranges()
            await server.refresh_cloudflare_ranges(texts=(v4_text(9), TEXT6))
            check("(a list is pending)", await d.get_setting(server.CF_SETTING_PENDING) is not None)
            st = await server.refresh_cloudflare_ranges(texts=(v4_text(2), TEXT6))
            check("a later good refresh clears the older pending list",
                  st["ok"] and await d.get_setting(server.CF_SETTING_PENDING) is None)

        with section('dismissal'):
            await server.reset_cloudflare_ranges()
            await d.conn.execute("DELETE FROM security_events")
            await d.conn.commit()
            await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            pend = json.loads(await d.get_setting(server.CF_SETTING_PENDING))
            code, _ = await server.dismiss_cloudflare_pending("f" * 16)
            check("dismissing another list id is a 409", code == 409 and await d.get_setting(server.CF_SETTING_PENDING) is not None)
            code, body = await server.dismiss_cloudflare_pending(pend["id"])
            check("dismissal removes the pending list and changes nothing in use",
                  code == 200 and body == {"v4": len(V4) + 8, "v6": len(V6)}
                  and await d.get_setting(server.CF_SETTING_PENDING) is None and server._cf_source == "built-in")
            n = len(await events(d))
            await server.refresh_cloudflare_ranges(texts=(t4, TEXT6))
            check("a dismissed list fetched again is not held again and writes no event",
                  await d.get_setting(server.CF_SETTING_PENDING) is None and len(await events(d)) == n)
            await server.refresh_cloudflare_ranges(texts=(v4_text(9), TEXT6))
            check("a different refused list is held after a dismissal", await d.get_setting(server.CF_SETTING_PENDING) is not None)

        with section('a reset clears the pending list and the dismissal'):
            await server.reset_cloudflare_ranges()
            check("a reset clears the pending list and the dismissal",
                  await d.get_setting(server.CF_SETTING_PENDING) is None and await d.get_setting(server.CF_SETTING_DISMISSED) is None)

        with section('a reset during a refresh wins'):
            await server.reset_cloudflare_ranges()
            gate, started = asyncio.Event(), asyncio.Event()
            events_before = len(await events(d))
            real_fetch = ipguard.fetch_text

            async def slow_fetch(url, ssl_context=None):
                started.set()
                await gate.wait()
                return v4_text(2) if url.endswith("v4") else TEXT6

            ipguard.fetch_text = slow_fetch
            try:
                task = asyncio.create_task(server.refresh_cloudflare_ranges(urls=("https://x.invalid/v4", "https://x.invalid/v6")))
                await started.wait()
                # a list is in use, then the superadmin resets while the fetch is still running
                server._apply_cloudflare_networks(NETS() + [ipaddress.ip_network("45.200.0.0/16")], "fetched", "x")
                await d.set_setting(server.CF_SETTING_LIST, json.dumps({"v4": V4, "v6": V6, "fetched_at": "x"}))
                await server.reset_cloudflare_ranges()
                gate.set()
                st = await task
            finally:
                ipguard.fetch_text = real_fetch
            check("a reset during a refresh wins: the fetched result is discarded and the built-in list stays in use",
                  server._cf_source == "built-in" and not server._is_trusted_proxy("45.1.0.9") and st["ok"] is False
                  and st.get("discarded") is True and "reset" in st["message"], str(st))
            check("...nothing is saved or pending, and no event is written for the discarded result",
                  await d.get_setting(server.CF_SETTING_LIST) is None and await d.get_setting(server.CF_SETTING_PENDING) is None
                  and len(await events(d)) == events_before)
            # a refresh that finishes before the reset is not discarded (control)
            st = await server.refresh_cloudflare_ranges(texts=(v4_text(2), TEXT6))
            check("(control) a refresh that starts after the reset applies normally", st["ok"] and server._cf_source == "fetched")
            # a reset that lands between the fetch and the swap (the swap waits for the lock)
            await server.reset_cloudflare_ranges()
            lock = server._cf_lock()
            await lock.acquire()
            task = asyncio.create_task(server.refresh_cloudflare_ranges(texts=(v4_text(2), TEXT6)))
            await asyncio.sleep(0.05)
            lock.release()
            st = await task
            check("(control) the swap takes the lock: a refresh waiting on it still applies when no reset came",
                  st["ok"] and server._cf_source == "fetched")
            await server.reset_cloudflare_ranges()
            lock = server._cf_lock()
            await lock.acquire()
            task = asyncio.create_task(server.refresh_cloudflare_ranges(texts=(v4_text(2), TEXT6)))
            await asyncio.sleep(0.05)
            server._cf_generation += 1          # a reset happened while it waited
            lock.release()
            st = await task
            check("a reset counted while the result waits for the lock discards it", st.get("discarded") is True
                  and server._cf_source == "built-in", str(st))

        with section('why a saved list is ignored'):
            await server.reset_cloudflare_ranges()
            await d.set_setting(server.CF_SETTING_LIST, json.dumps({"v4": V4, "v6": V6, "fetched_at": "x"}))
            await d.set_setting(server.CF_SETTING_ENABLED, "false")
            await server._load_cloudflare_state()
            view = await server._cf_ranges_view()
            check("refresh off at start: the reason is refresh_off", view["saved_list_ignored"]
                  and view["saved_list_ignored_reason"] == "refresh_off", str(view))
            await d.set_setting(server.CF_SETTING_ENABLED, "true")
            view = await server._cf_ranges_view()
            check("the refresh switched on afterwards: the reason is still refresh_off (it was off at start)",
                  view["enabled"] and view["saved_list_ignored_reason"] == "refresh_off", str(view))
            await d.set_setting(server.CF_SETTING_LIST, json.dumps({"v4": V4 + ["45.0.0.0/8"], "v6": V6, "fetched_at": "x"}))
            await server._load_cloudflare_state()
            view = await server._cf_ranges_view()
            check("a saved list that failed the checks at start: the reason is failed_checks",
                  view["saved_list_ignored_reason"] == "failed_checks", str(view))
            await d.set_setting(server.CF_SETTING_ENABLED, "false")
            view = await server._cf_ranges_view()
            check("...also when the refresh is switched off afterwards", view["saved_list_ignored_reason"] == "failed_checks", str(view))
            await d.set_setting(server.CF_SETTING_ENABLED, "true")
            await server.reset_cloudflare_ranges()
            view = await server._cf_ranges_view()
            check("nothing ignored: the reason is null", view["saved_list_ignored_reason"] is None
                  and view["pending"] is None, str(view))
    finally:
        server._apply_cloudflare_networks(NETS(), "built-in")
        secevents.log.bind(None)
        await d.close()


asyncio.run(main())

# ---------------------------------------------------------------------------
# The page: text and wiring (a fake render of the real template strings, no browser)
# ---------------------------------------------------------------------------

html = (Path(SRC) / "static" / "admin.html").read_text(encoding="utf-8")
check("the panel has one text for refresh-off-at-start and one for failed checks, chosen by the reason from the server",
      "saved_list_ignored_reason === 'refresh_off'" in html and "saved_list_ignored_reason !== 'refresh_off'" in html
      and "the weekly refresh was off when the portal started" in html and "failed the checks when the portal started" in html)
check("the old wording that guessed the reason from the refresh switch is gone",
      "c.saved_list_ignored && !c.enabled" not in html and "c.saved_list_ignored && c.enabled" not in html)
check("the reset button and its confirmation say a fetched list returns at the next scheduled refresh",
      html.count("a fetched list returns at the next scheduled refresh") == 2)
check("the panel shows the pending list with approve and dismiss, and sends the list id",
      "renderCfPending(c.pending)" in html and 'data-cfranges-action="approve"' in html
      and 'data-cfranges-action="dismiss"' in html and "/api/admin/cf-ranges/pending/" in html
      and "JSON.stringify({ id })" in html)
check("every value of the pending list is escaped when shown",
      all(s in html for s in ("escapeHtml(p.reason", "escapeHtml(p.id)", "escapeHtml(p.fetched_at", "escapeHtml(x)")))
check("the new events are in the page's event list",
      "'cf_ranges_approved'" in html and "'cf_ranges_dismissed'" in html)
src = (Path(SRC) / "server.py").read_text(encoding="utf-8")
for name in ("http_approve_cf_pending", "http_dismiss_cf_pending"):
    i = src.index(f"async def {name}")
    body = src[i:src.index("\nasync def ", i + 10)]
    check(f"{name} asks for a superadmin's browser session (a full-scope token is refused)",
          "_cf_pending_request" in body)
i = src.index("async def _cf_pending_request")
check("the shared start of both routes uses the cookie-only superadmin guard",
      "_backup_superadmin(request, cookie_only=True)" in src[i:src.index("\nasync def ", i + 10)])
check("both routes are registered", "/api/admin/cf-ranges/pending/approve" in src and "/api/admin/cf-ranges/pending/dismiss" in src)

print()
if failures:
    print(f"{len(failures)} check(s) FAILED: " + "; ".join(failures))
    sys.exit(1)
print("all checks passed")
