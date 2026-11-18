"""Cloudflare range refresh: list validation, the atomic swap, persistence and the fetcher.

The fetcher is tested against a local HTTPS server with a self-signed certificate
(the real lists are never requested).

Run:  venv/bin/python tests/test_cf_ranges.py
      PORTAL_SRC=/path/to/other/tree venv/bin/python tests/test_cf_ranges.py
"""

import asyncio
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = os.environ.get("PORTAL_SRC") or str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SRC)

_TMP = tempfile.TemporaryDirectory()
# Own database only: a .env next to the code (a staged copy has one) can override the environment,
# so the path is kept in a variable and every Database() below is given it explicitly.
TEST_DB = str(Path(_TMP.name) / "cf.db")
os.environ["DATABASE_PATH"] = TEST_DB
os.environ.setdefault("JWT_SECRET", "x" * 64)

from aiohttp import web  # noqa: E402

import ipguard  # noqa: E402
import server  # noqa: E402
from config import Config  # noqa: E402
from database import Database  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


BUILTIN = list(server._CLOUDFLARE_NETWORKS)
V4 = [n for n in BUILTIN if ":" not in n]
V6 = [n for n in BUILTIN if ":" in n]
NEW_V4 = "45.0.0.0/16"          # a global range that is not in the built-in list
TEXT4 = "\n".join(V4) + "\n"
TEXT6 = "\n".join(V6) + "\n"


def refused(t4, t6, current=None):
    try:
        ipguard.validate_cf_lists(t4, t6, current)
    except ipguard.ListError as e:
        return str(e)
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

check("the built-in list passes the same validation", refused(TEXT4, TEXT6) is None)
check("a list with one more range passes", refused(TEXT4 + NEW_V4 + "\n", TEXT6) is None)
check("blank lines and surrounding spaces are tolerated", refused("\n\n  " + TEXT4.replace("\n", "  \n") + "\n", TEXT6) is None)
check("duplicates are collapsed", len(ipguard.validate_cf_lists(TEXT4 + V4[0] + "\n", TEXT6)) == len(BUILTIN))

bad_lines = {
    "a text line": "hello",
    "an HTML page": "<html><body>403</body></html>",
    "a host name": "example.com",
    "a v6 range in the v4 list": "2400:cb00::/32",
    "a range broader than /8": "64.0.0.0/7",
    "everything": "0.0.0.0/0",
    "a private range": "172.16.0.0/12",
    "a private /16": "192.168.0.0/16",
    "loopback": "127.0.0.0/8",
    "link-local": "169.254.0.0/16",
    "carrier-grade NAT": "100.64.0.0/10",
    "multicast": "224.0.0.0/8",
    "a reserved range": "240.0.0.0/8",
    "host bits set": "173.245.48.1/20",
    "a netmask": "173.245.48.0/255.255.240.0",
}
for label, line in bad_lines.items():
    check(f"validation refuses {label} in the v4 list", refused(TEXT4 + line + "\n", TEXT6) is not None)
bad6 = {
    "a v4 range in the v6 list": "104.16.0.0/13",
    "::/0": "::/0",
    "a prefix shorter than /16": "2000::/15",
    "loopback": "::1/128",
    "unique local": "fd00::/16",
    "documentation": "2001:db8::/32",
    "link-local": "fe80::/16",
    "multicast": "ff00::/16",
}
for label, line in bad6.items():
    check(f"validation refuses {label} in the v6 list", refused(TEXT4, TEXT6 + line + "\n") is not None)
check("an empty answer is refused", refused("", "") is not None)
check("too few IPv4 ranges are refused", "at least 10" in (refused("\n".join(V4[:9]), TEXT6) or ""))
check("exactly 10 IPv4 ranges are accepted", refused("\n".join(V4[:10]), TEXT6) is None)
check("too few IPv6 ranges are refused", "at least 5" in (refused(TEXT4, "\n".join(V6[:4])) or ""))
check("exactly 5 IPv6 ranges are accepted", refused(TEXT4, "\n".join(V6[:5])) is None)
B4 = [ipaddress.ip_network(n) for n in V4]
B6 = [ipaddress.ip_network(n) for n in V6]
check("the broadest built-in range sets the floor: /13 IPv4 and /29 IPv6",
      min(n.prefixlen for n in B4) == 13 and min(n.prefixlen for n in B6) == 29)
check("a /13 (the broadest built-in IPv4 range) is accepted: it is already in the list", refused(TEXT4, TEXT6) is None)
check("a /12 in the IPv4 list is refused", "broader" in (refused(TEXT4 + "45.0.0.0/12\n", TEXT6) or ""))
check("a /8 in the IPv4 list is refused", refused(TEXT4 + "45.0.0.0/8\n", TEXT6) is not None)
check("a /28 in the IPv6 list is refused", "broader" in (refused(TEXT4, TEXT6 + "2a00::/28\n") or ""))
check("a /29 in the IPv6 list is accepted", refused(TEXT4, TEXT6 + "2a07::/29\n") is None)
check("a /16 IPv6 range, which the old rule allowed, is refused", refused(TEXT4, TEXT6 + "2a00::/16\n") is not None)

# Probe 1: three extra /8s (the old rule accepted them)
probe1 = TEXT4 + "1.0.0.0/8\n2.0.0.0/8\n3.0.0.0/8\n"
check("probe: three extra /8 ranges are refused", refused(probe1, TEXT6) is not None)
check("probe: three extra /8 ranges are refused against a fetched current list too", refused(probe1, TEXT6, B4 + B6) is not None)
# Probe 2: every IPv6 range replaced by unrelated /32s
probe2 = "\n".join(f"2a0{i}:1::/32" for i in range(1, 6)) + "\n"
check("probe: all IPv6 ranges replaced by five unrelated /32s are refused", "built-in" in (refused(TEXT4, probe2) or ""),
      str(refused(TEXT4, probe2)))
check("probe: the same replacement is refused when the current list is a fetched one", refused(TEXT4, probe2, B4 + B6) is not None)

# At most 5 new ranges per family in one refresh
new4 = lambda n: "".join(f"45.{i}.0.0/16\n" for i in range(n))  # noqa: E731
new6 = lambda n: "".join(f"2a0{i}::/32\n" for i in range(n))  # noqa: E731
check("5 new IPv4 ranges are accepted", refused(TEXT4 + new4(5), TEXT6) is None)
check("6 new IPv4 ranges are refused", "6 new IPv4" in (refused(TEXT4 + new4(6), TEXT6) or ""))
check("5 new IPv6 ranges are accepted", refused(TEXT4, TEXT6 + new6(5)) is None)
check("6 new IPv6 ranges are refused", "6 new IPv6" in (refused(TEXT4, TEXT6 + new6(6)) or ""))
check("5 new in each family at once are accepted", refused(TEXT4 + new4(5), TEXT6 + new6(5)) is None)
cur_plus = B4 + B6 + [ipaddress.ip_network(f"45.{i}.0.0/16") for i in range(6)]
check("ranges already trusted do not count as new: six more are fine when the current list holds them",
      refused(TEXT4 + new4(6), TEXT6, cur_plus) is None)
check("a range inside a current range is not new",
      refused(TEXT4 + "".join(f"104.16.{i}.0/24\n" for i in range(8)), TEXT6) is None)
cur_small = [ipaddress.ip_network(n) for n in V4[:10] + ["162.158.0.0/15"]] + B6
check("a range that contains a current range is new (a broadened range)",
      "6 new IPv4" in (refused("\n".join(V4[:10]) + "\n162.152.0.0/13\n" + new4(5), TEXT6, cur_small) or "")
      and refused("\n".join(V4[:10]) + "\n162.158.0.0/15\n" + new4(5), TEXT6, cur_small) is None)
check("a load of a saved list skips the new-range count, not the other rules",
      ipguard.validate_cf_lists(TEXT4 + new4(9), TEXT6, compare_new=False) is not None)
try:
    ipguard.validate_cf_lists(TEXT4 + "45.0.0.0/8\n", TEXT6, compare_new=False)
    loaded_broad = False
except ipguard.ListError:
    loaded_broad = True
check("a saved list with a too-broad range is refused at load as well", loaded_broad)
try:
    ipguard.validate_cf_lists(TEXT4, probe2, compare_new=False)
    loaded_swapped = False
except ipguard.ListError:
    loaded_swapped = True
check("a saved list with the IPv6 ranges replaced is refused at load as well", loaded_swapped)

# Shrink rule: per family, against the built-in list (a range that equals or contains one still counts)
check("IPv4: keeping 8 of 15 built-in ranges is enough",
      refused("\n".join(V4[:8]) + "\n" + new4(3), TEXT6) is None)
check("IPv4: keeping 7 of 15 built-in ranges is refused (CF_MIN_V4 alone would pass 10)",
      "drops 8 of 15 built-in" in (refused("\n".join(V4[:7]) + "\n" + new4(3), TEXT6) or ""))
check("IPv6: keeping 4 of 7 built-in ranges is enough, with one new range",
      refused(TEXT4, "\n".join(V6[:4]) + "\n" + new6(1)) is None)
check("IPv6: keeping 3 of 7 built-in ranges is refused",
      "drops 4 of 7 built-in" in (refused(TEXT4, "\n".join(V6[:3]) + "\n" + new6(2)) or ""))
check("a fetched range that contains a built-in range counts as keeping it",
      refused("\n".join(V4[:10]) + "\n162.0.0.0/13\n104.0.0.0/13\n", TEXT6) is None)
check("the shrink rule is per family: a good IPv4 list does not excuse a bad IPv6 list",
      refused(TEXT4, "\n".join(V6[:3]) + "\n" + new6(2)) is not None)
check("the shrink rule also applies against the current list, per family",
      "current" in (refused(TEXT4, TEXT6, B4 + B6 + [ipaddress.ip_network(f"2a0{i}::/32") for i in range(1, 9)]) or ""))

# ---------------------------------------------------------------------------
# The swap, persistence and the settings keys (real database)
# ---------------------------------------------------------------------------

async def swap_cases():
    d = Database(TEST_DB)
    await d.connect()
    server.db = d
    import secevents
    secevents.log.bind(d)
    builtin_nets = [ipaddress.ip_network(n) for n in BUILTIN]
    try:
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        server._extra_trusted_networks[:] = [ipaddress.ip_network("127.0.0.1/32")]
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        probe_ip = "45.0.1.1"
        check("before: an address in the new range is not trusted (and that answer is cached)",
              server._is_trusted_proxy(probe_ip) is False and probe_ip in server._trusted_peer_cache)

        st = await server.refresh_cloudflare_ranges(texts=(TEXT4 + NEW_V4 + "\n", TEXT6))
        check("refresh with a good list reports ok", st["ok"] and st["added"] == [NEW_V4] and st["removed"] == [], str(st))
        check("a newly added range is trusted at once, without a restart (cache cleared)",
              server._is_trusted_proxy(probe_ip) is True)
        check("the TRUSTED_PROXIES entries survive the swap", server._is_trusted_proxy("127.0.0.1") is True)
        check("the combined list is the Cloudflare part plus TRUSTED_PROXIES",
              len(server._trusted_proxy_networks) == len(BUILTIN) + 2)
        check("the source is shown as fetched", server._cf_source == "fetched" and server._cf_fetched_at)
        saved = json.loads(await d.get_setting(server.CF_SETTING_LIST))
        check("the last good list is saved in settings", NEW_V4 in saved["v4"] and len(saved["v6"]) == len(V6))
        last = json.loads(await d.get_setting(server.CF_SETTING_LAST))
        check("the result and time are saved in settings", last["ok"] is True and last["at"] and last["last_ok_at"])

        # poisoned answers change nothing
        snapshot = list(server._trusted_proxy_networks)
        for label, texts in {
            "an empty answer": ("", ""),
            "an HTML error page": ("<html>blocked</html>", "<html>blocked</html>"),
            "too few ranges": ("\n".join(V4[:3]), "\n".join(V6[:2])),
            "a private range slipped in": (TEXT4 + "10.0.0.0/16\n", TEXT6),
            "everything": (TEXT4 + "0.0.0.0/0\n", TEXT6),
            "most trusted ranges missing": ("\n".join(f"60.{i}.0.0/16" for i in range(12)), "\n".join(f"2a0{i}::/32" for i in range(1, 7))),
        }.items():
            st = await server.refresh_cloudflare_ranges(texts=texts)
            check(f"{label}: refused, list unchanged, failure recorded",
                  st["ok"] is False and server._trusted_proxy_networks == snapshot and st["message"]
                  and st["last_ok_at"], str(st))
        last = json.loads(await d.get_setting(server.CF_SETTING_LAST))
        check("the failure is what the admin page will show, with the last good time kept",
              last["ok"] is False and last["last_ok_at"])
        check("the saved good list is still the good one", NEW_V4 in json.loads(await d.get_setting(server.CF_SETTING_LIST))["v4"])

        # restart: the saved list is used, a damaged saved list is ignored
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        check("after a 'restart' the built-in list is back", server._is_trusted_proxy(probe_ip) is False)
        await server._load_cloudflare_state()
        check("the saved list is loaded at startup", server._is_trusted_proxy(probe_ip) is True and server._cf_source == "fetched")
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        await d.set_setting(server.CF_SETTING_LIST, json.dumps({"v4": ["0.0.0.0/0"], "v6": V6, "fetched_at": "x"}))
        await server._load_cloudflare_state()
        check("a damaged saved list is ignored and the built-in list stays",
              server._cf_source == "built-in" and server._is_trusted_proxy("173.245.48.5") and not server._is_trusted_proxy("1.2.3.4"))
        await d.set_setting(server.CF_SETTING_LIST, "not json")
        await server._load_cloudflare_state()
        check("an unreadable saved list is ignored", server._cf_source == "built-in")

        # staged mode never goes out
        Config.STAGE_MODE = True
        try:
            st = await server.refresh_cloudflare_ranges()
        finally:
            Config.STAGE_MODE = False
        check("a staged instance refuses to fetch", st["ok"] is False and "staged" in st["message"], str(st))
        import secevents
        cur = await d.conn.execute("SELECT * FROM security_events WHERE event = 'cf_ranges_refreshed' ORDER BY id")
        evs = [dict(x) for x in await cur.fetchall()]
        ok_ev = [e for e in evs if e["result"] == "ok"]
        bad_ev = [e for e in evs if e["result"] == "failed"]
        check("every refresh is a security event: the success carries the counts",
              len(ok_ev) == 1 and json.loads(ok_ev[0]["details"]) == {
                  "v4": len(V4) + 1, "v6": len(V6), "added": 1, "removed": 0}
              and ok_ev[0]["category"] == "security" and ok_ev[0]["ip"] == "system", str(ok_ev))
        check("every failed refresh is an event with the reason",
              len(bad_ev) == 7 and all(json.loads(e["details"]).get("reason") for e in bad_ev)
              and "staged" in json.loads(bad_ev[-1]["details"])["reason"], str(bad_ev[-2:]))
        # with a fetch error nothing changes either
        st = await server.refresh_cloudflare_ranges(urls=("https://127.0.0.1:9/ips-v4", "https://127.0.0.1:9/ips-v6"))
        check("an unreachable source keeps the built-in list and records the failure",
              st["ok"] is False and server._cf_source == "built-in" and server._is_trusted_proxy("173.245.48.5"), str(st))
    finally:
        server._extra_trusted_networks[:] = server._parse_extra_trusted()
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        secevents.log.bind(None)
        await d.close()


asyncio.run(swap_cases())

# ---------------------------------------------------------------------------
# Due schedule
# ---------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

now = datetime.now(timezone.utc)
f = lambda dt: dt.strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731
check("due: never run", server._cf_refresh_due({}, now))
check("due: garbage time", server._cf_refresh_due({"at": "x", "ok": True}, now))
check("not due: a success an hour ago", not server._cf_refresh_due({"at": f(now - timedelta(hours=1)), "ok": True}, now))
check("not due: a success six days ago", not server._cf_refresh_due({"at": f(now - timedelta(days=6)), "ok": True}, now))
check("due: a success eight days ago", server._cf_refresh_due({"at": f(now - timedelta(days=8)), "ok": True}, now))
check("not due: a failure an hour ago (retry after a day)", not server._cf_refresh_due({"at": f(now - timedelta(hours=1)), "ok": False}, now))
check("due: a failure two days ago", server._cf_refresh_due({"at": f(now - timedelta(days=2)), "ok": False}, now))

# ---------------------------------------------------------------------------
# The fetcher, against a local HTTPS server
# ---------------------------------------------------------------------------

cert, key = Path(_TMP.name) / "c.pem", Path(_TMP.name) / "k.pem"
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", str(key),
                "-out", str(cert), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
               capture_output=True, check=True)
server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(str(cert), str(key))
client_ctx = ssl.create_default_context(cafile=str(cert))

seen_requests = []


async def serve_text(text):
    async def h(request):
        seen_requests.append(dict(request.headers))
        resp = web.Response(text=text, content_type="text/plain")
        resp.set_cookie("session", "tracking")
        return resp
    return h


async def fetch_cases():
    app = web.Application()
    app.router.add_get("/ips-v4", await serve_text(TEXT4 + NEW_V4 + "\n"))
    app.router.add_get("/ips-v6", await serve_text(TEXT6))
    app.router.add_get("/big", await serve_text("1.2.3.0/24\n" * 8000))
    app.router.add_get("/binary", await serve_text("caf\u00e9\n"))
    app.router.add_get("/missing", lambda r: web.Response(status=404))

    async def slow(request):
        await asyncio.sleep(5)
        return web.Response(text="late")

    async def redirect_other(request):
        raise web.HTTPFound("https://example.org/ips-v4")

    async def redirect_same(request):
        raise web.HTTPFound("/ips-v4")

    async def loop(request):
        raise web.HTTPFound("/loop")
    app.router.add_get("/slow", slow)
    app.router.add_get("/redir-other", redirect_other)
    app.router.add_get("/redir-same", redirect_same)
    app.router.add_get("/loop", loop)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_ctx)
    await site.start()
    base = f"https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        async def err(path, ctx=client_ctx):
            try:
                await ipguard.fetch_text(base + path, ctx)
            except ipguard.FetchError as e:
                return str(e)
            return None

        text = await ipguard.fetch_text(base + "/ips-v4", client_ctx)
        check("fetch: a good list is returned", NEW_V4 in text)
        req = seen_requests[-1]
        check("fetch: no cookie, no credential and a generic user agent are sent",
              "Cookie" not in req and "Authorization" not in req and req.get("User-Agent") == ipguard.CF_USER_AGENT
              and "portal" not in req.get("User-Agent", "").lower(), str(req))
        await ipguard.fetch_text(base + "/ips-v4", client_ctx)
        check("fetch: a cookie the server sets is not sent back (no cookie jar)", "Cookie" not in seen_requests[-1])
        check("fetch: certificate verification is on (a self-signed server is refused without the injected CA)",
              await err("/ips-v4", None) == "certificate verification failed", str(await err("/ips-v4", None)))
        check("fetch: a plain http URL is refused", "https" in (await _err_url("http://127.0.0.1:1/ips-v4")))
        check("fetch: a 404 is a failure", "404" in (await err("/missing") or ""))
        check("fetch: a body over 64 KB is refused", "64 KB" in (await err("/big") or ""))
        check("fetch: a non-ASCII body is refused", "ASCII" in (await err("/binary") or ""))
        check("fetch: a redirect to another host is refused", "different host" in (await err("/redir-other") or ""))
        check("fetch: a redirect within the same host is followed", await err("/redir-same") is None)
        check("fetch: a redirect loop ends", "redirect" in (await err("/loop") or ""))
        saved_to = ipguard.CF_TIMEOUT_SECONDS
        ipguard.CF_TIMEOUT_SECONDS = 1
        try:
            check("fetch: a slow server times out", "timed out" in (await err("/slow") or ""))
        finally:
            ipguard.CF_TIMEOUT_SECONDS = saved_to
        check("fetch: the timeout is 10 seconds", saved_to == 10 and ipguard.CF_MAX_BYTES == 65536)
        check("fetch: the published list URLs are the two plain-text Cloudflare lists over https",
              ipguard.CF_URLS == ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"))

        # end to end through the server's refresh
        d = Database(TEST_DB)
        await d.connect()
        server.db = d
        builtin_nets = [ipaddress.ip_network(n) for n in BUILTIN]
        try:
            server._apply_cloudflare_networks(builtin_nets, "built-in")
            st = await server.refresh_cloudflare_ranges(urls=(base + "/ips-v4", base + "/ips-v6"), ssl_context=client_ctx)
            check("end to end: a refresh through the local server adds the new range without a restart",
                  st["ok"] and server._is_trusted_proxy("45.0.9.9") and st["added"] == [NEW_V4], str(st))
            st = await server.refresh_cloudflare_ranges(urls=(base + "/ips-v4", base + "/ips-v6"), ssl_context=None)
            check("end to end: without the CA the refresh fails and the list is unchanged",
                  not st["ok"] and "certificate" in st["message"] and server._is_trusted_proxy("45.0.9.9"), str(st))
            st = await server.refresh_cloudflare_ranges(urls=(base + "/missing", base + "/ips-v6"), ssl_context=client_ctx)
            check("end to end: a blocked fetch keeps the list and shows the failure",
                  not st["ok"] and "404" in st["message"], str(st))
        finally:
            server._apply_cloudflare_networks(builtin_nets, "built-in")
            await d.close()
    finally:
        await runner.cleanup()


async def _err_url(url):
    try:
        await ipguard.fetch_text(url, client_ctx)
    except ipguard.FetchError as e:
        return str(e)
    return ""


asyncio.run(fetch_cases())

# ---------------------------------------------------------------------------
# A way back to the built-in list: refresh off, reset in the server, reset from the command line
# ---------------------------------------------------------------------------

async def reset_cases():
    import secevents
    d = Database(TEST_DB)
    await d.connect()
    server.db = d
    secevents.log.bind(d)
    builtin_nets = [ipaddress.ip_network(n) for n in BUILTIN]
    probe_ip = "45.0.1.1"
    try:
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        await d.set_setting(server.CF_SETTING_ENABLED, "true")
        st = await server.refresh_cloudflare_ranges(texts=(TEXT4 + NEW_V4 + "\n", TEXT6))
        check("setup: a fetched list is saved and applied", st["ok"] and server._is_trusted_proxy(probe_ip))
        view = await server._cf_ranges_view()
        check("the view says a saved list is in use", view["saved_list"] and view["saved_list_applied"]
              and not view["saved_list_ignored"], str(view))

        server._apply_cloudflare_networks(builtin_nets, "built-in")
        await d.set_setting(server.CF_SETTING_ENABLED, "false")
        await server._load_cloudflare_state()
        check("refresh off: the saved list is not applied at start, the built-in list is used",
              server._cf_source == "built-in" and not server._is_trusted_proxy(probe_ip))
        check("refresh off: the saved list is kept", bool(await d.get_setting(server.CF_SETTING_LIST)))
        view = await server._cf_ranges_view()
        check("refresh off: the view says the saved list is kept but not applied",
              view["saved_list"] and not view["saved_list_applied"] and view["saved_list_ignored"]
              and view["enabled"] is False, str(view))

        await d.set_setting(server.CF_SETTING_ENABLED, "true")
        await server._load_cloudflare_state()
        check("refresh switched on again: the saved list is applied at the next start",
              server._cf_source == "fetched" and server._is_trusted_proxy(probe_ip))

        before = await server.reset_cloudflare_ranges()
        check("reset: the built-in list is in use at once, without a restart",
              server._cf_source == "built-in" and not server._is_trusted_proxy(probe_ip)
              and server._is_trusted_proxy("173.245.48.5") and server._cf_fetched_at is None)
        check("reset: it reports what was replaced", before["source"] == "fetched" and before["v4"] == len(V4) + 1, str(before))
        check("reset: the saved list is cleared", await d.get_setting(server.CF_SETTING_LIST) is None)
        await server._load_cloudflare_state()
        check("reset: it stays reset after a restart", server._cf_source == "built-in")
        view = await server._cf_ranges_view()
        check("reset: the view shows no saved list", not view["saved_list"] and not view["saved_list_ignored"], str(view))
        check("reset: the combined trusted list is the built-in part plus TRUSTED_PROXIES",
              len(server._trusted_proxy_networks) == len(BUILTIN) + len(server._extra_trusted_networks))
        check("the reset event is a known security event with the security category",
              secevents.EVENTS.get("cf_ranges_reset") == "security")
    finally:
        server._apply_cloudflare_networks(builtin_nets, "built-in")
        secevents.log.bind(None)
        await d.close()


asyncio.run(reset_cases())

import contextlib  # noqa: E402
import io  # noqa: E402
import sqlite3  # noqa: E402
import ban_cli  # noqa: E402


def run_cli(fn, *a):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        try:
            rc = fn(*a)
        except SystemExit as e:
            rc = e.code
    return rc, buf.getvalue() + err.getvalue()


def schema_of(path):
    c = sqlite3.connect(path)
    try:
        return c.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
    finally:
        c.close()


async def make_cli_db(path, saved=True):
    d = Database(path)
    await d.connect()
    if saved:
        await d.set_setting(server.CF_SETTING_LIST, json.dumps({"v4": V4, "v6": V6, "fetched_at": "x"}))
        await d.set_setting(server.CF_SETTING_ENABLED, "true")
    await d.close()


with tempfile.TemporaryDirectory() as tmp:
    path = str(Path(tmp) / "cli.db")
    asyncio.run(make_cli_db(path))
    before = schema_of(path)
    rc, out = run_cli(ban_cli.cf_ranges_reset, path)
    c = sqlite3.connect(path)
    left = c.execute("SELECT COUNT(*) FROM settings WHERE key = ?", (server.CF_SETTING_LIST,)).fetchone()[0]
    kept = c.execute("SELECT value FROM settings WHERE key = ?", (server.CF_SETTING_ENABLED,)).fetchone()
    ev = c.execute("SELECT event, category, ip, result, details, count FROM security_events").fetchall()
    c.close()
    check("cf-ranges-reset clears the saved list, leaves the other settings and says to restart",
          rc == 0 and left == 0 and kept and kept[0] == "true" and "Restart the portal" in out, out)
    check("cf-ranges-reset records one cf_ranges_reset security event from the command line",
          len(ev) == 1 and ev[0][0] == "cf_ranges_reset" and ev[0][1] == "security" and ev[0][2] == "cli"
          and json.loads(ev[0][4]).get("kind") == "cli" and ev[0][5] == 1, str(ev))
    check("cf-ranges-reset does not change the schema", schema_of(path) == before)
    rc, out = run_cli(ban_cli.cf_ranges_reset, path)
    c = sqlite3.connect(path)
    n = c.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    c.close()
    check("cf-ranges-reset with nothing saved says so and records nothing", rc == 0 and "no saved" in out and n == 1, out)
    rc, out = run_cli(ban_cli.cf_ranges_reset, str(Path(tmp) / "missing.db"))
    check("cf-ranges-reset refuses a missing database and creates none",
          rc not in (0, None) and not (Path(tmp) / "missing.db").exists(), out)
    bare = str(Path(tmp) / "bare.db")
    sqlite3.connect(bare).close()
    rc, out = run_cli(ban_cli.cf_ranges_reset, bare)
    check("cf-ranges-reset tolerates a database with no tables and migrates nothing",
          rc == 0 and schema_of(bare) == [], out)
    if (Path(SRC) / ".env").exists():
        print("skip: the entry-point test needs a tree without a .env (the staged smoke check covers it)")
    else:
        path2 = str(Path(tmp) / "entry.db")
        asyncio.run(make_cli_db(path2))
        env = dict(os.environ, DATABASE_PATH=path2, JWT_SECRET="x" * 64)
        res = subprocess.run([sys.executable, "server.py", "cf-ranges-reset"], cwd=SRC, env=env,
                             capture_output=True, text=True, timeout=120)
        c = sqlite3.connect(path2)
        n = c.execute("SELECT COUNT(*) FROM settings WHERE key = ?", (server.CF_SETTING_LIST,)).fetchone()[0]
        c.close()
        check("server.py cf-ranges-reset works through the real entry point", res.returncode == 0 and n == 0,
              res.stdout + res.stderr)

print()
if failures:
    print(f"{len(failures)} check(s) FAILED: " + "; ".join(failures))
    sys.exit(1)
print("all checks passed")
