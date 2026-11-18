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
check("a /8 is accepted, the broadest allowed", refused(TEXT4 + "45.0.0.0/8\n", TEXT6) is None)
cur = [ipaddress.ip_network(n) for n in BUILTIN]
unrelated4 = "\n".join(f"60.{i}.0.0/16" for i in range(10))
check("a list that keeps only 5 of 22 current ranges is refused",
      "drops 17 of 22" in (refused(unrelated4, "\n".join(V6[:5]), cur) or ""))
check("a list that keeps 15 of 22 current ranges is accepted", refused("\n".join(V4[:10]), "\n".join(V6[:5]), cur) is None)
many = [ipaddress.ip_network(f"60.{i}.0.0/16") for i in range(22)]
keep11 = "\n".join(str(n) for n in many[:11])
keep10 = "\n".join(str(n) for n in many[:10])
check("dropping exactly half (11 of 22) is allowed: only MORE than half is refused", refused(keep11, TEXT6, many) is None)
check("dropping 12 of 22 is refused", refused(keep10, TEXT6, many) is not None)
agg4 = "\n".join(V4[:10]) + "\n162.0.0.0/8\n104.0.0.0/8\n"
check("a supernet that covers current ranges is not counted as dropping them",
      refused(agg4, TEXT6, [ipaddress.ip_network(n) for n in ("162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14")]) is None)

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

print()
if failures:
    print(f"{len(failures)} check(s) FAILED: " + "; ".join(failures))
    sys.exit(1)
print("all checks passed")
