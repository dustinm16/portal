"""The share dialog's note on how a web connection is shown to the people it is shared with (1.24.1).

proxy_origin.decide gives "trusted" (no sandbox) to a web connection owned by an administrator that is not
in browser mode, and "isolated" to the rest. The dialog must not tell an administrator that such a
connection runs in a sandbox. showShareConnectionModal runs under node with a fake document (no browser).

Run: venv/bin/python tests/test_share_note_ui.py
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
index = (ROOT / "static" / "index.html").read_text()
js = (ROOT / "static" / "js" / "user-connections.js").read_text()
failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


check("index.html has both notes", 'id="share-web-isolation-note"' in index and 'id="share-web-trusted-note"' in index)
m = re.search(r"async function showShareConnectionModal\(.*?\n}\n", js, re.S)
check("showShareConnectionModal is present", m is not None)
if m:
    script = """
const els = {};
const mk = () => ({ style: {}, value: '', textContent: '' });
for (const id of ['share-conn-uuid', 'share-conn-name', 'share-duration', 'share-stored-password-warning',
                  'share-web-isolation-note', 'share-web-trusted-note', 'share-connection-modal']) els[id] = mk();
global.document = { getElementById: (id) => els[id] || null };
global.showModal = () => {};
global.initUserPicker = () => ({ reset: () => {} });
global.loadConnectionShares = async () => {};
global.Portal = { isAdmin: (u) => !!u && (u.is_admin || u.role === 'superadmin' || u.role === 'admin') };
let _sharePicker = null, _shareExisting = new Set();
""" + m.group(0) + """
async function run(user, conn) {
  global.currentUser = user;
  global.userConnections = conn ? [conn] : [];
  els['share-web-isolation-note'].style.display = '';
  els['share-web-trusted-note'].style.display = '';
  await showShareConnectionModal('c1', 'x');
  return { isolated: els['share-web-isolation-note'].style.display, trusted: els['share-web-trusted-note'].style.display };
}
(async () => {
  const out = {};
  out.memberWeb = await run({ role: 'user' }, { id: 'c1', name: 'x', config: {} });
  out.memberBrowser = await run({ role: 'user' }, { id: 'c1', name: 'x', config: { browser_mode: true } });
  out.adminWeb = await run({ role: 'admin' }, { id: 'c1', name: 'x', config: {} });
  out.superWeb = await run({ role: 'superadmin' }, { id: 'c1', name: 'x', config: {} });
  out.adminBrowser = await run({ role: 'admin' }, { id: 'c1', name: 'x', config: { browser_mode: true } });
  out.adminFlag = await run({ role: 'user', is_admin: true }, { id: 'c1', name: 'x', config: {} });
  console.log(JSON.stringify(out));
})();
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        try:
            r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
        except subprocess.TimeoutExpired:
            r = None
    got = json.loads(r.stdout) if r is not None and r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the function", bool(got), (r.stderr[-300:] if r is not None else "timeout"))
    sandboxed = {"isolated": "block", "trusted": "none"}
    trusted = {"isolated": "none", "trusted": "block"}
    check("a member sharing a web connection sees the sandbox note only", got.get("memberWeb") == sandboxed, str(got.get("memberWeb")))
    check("anybody sharing a connection in browser mode sees the sandbox note only (it is isolated whoever owns it)",
          got.get("memberBrowser") == sandboxed and got.get("adminBrowser") == sandboxed, str(got))
    check("an administrator sharing a web connection not in browser mode sees the trusted note, not the sandbox claim",
          got.get("adminWeb") == trusted and got.get("superWeb") == trusted and got.get("adminFlag") == trusted, str(got))

# (1.24.2, E9) Continue only goes to this connection's own address: a dot segment, plain or percent-encoded,
# would normalise to another portal page, so it falls back to the default /browser address.
sys.path.insert(0, str(ROOT / "tests"))
try:
    from grant_harness import server as _server  # noqa: E402
    nxt = _server._safe_notice_next
except Exception as exc:                                    # the harness is missing: say so, do not crash
    nxt = None
    check("E9: the server module loads for the next-address test", False, repr(exc))
if nxt:
    cid = "AbCdEf123"
    default = f"/browser?connection={cid}"
    for bad in (f"/proxy/{cid}/../../logout", f"/proxy/{cid}/%2e%2e/%2e%2e/logout", f"/proxy/{cid}/%2E%2e/logout",
                f"/proxy/{cid}/.%2e/logout", f"/proxy/{cid}/%2e./logout", f"/proxy/{cid}/./x", f"/proxy/{cid}/a/../../../logout",
                f"/proxy/{cid}/..\\..\\logout", f"/proxy/{cid}/%2e%2e%2flogout", f"/proxy/{cid}/%252e%252e/logout",
                f"/proxy/{cid}/..?x=1", f"/proxy/{cid}/%2e%2e#frag",
                f"/proxy/{cid}/ok/%2e%2e/../x",
                # an ASCII tab, line feed or carriage return inside a dot segment is dropped by the browser's URL parser
                f"/proxy/{cid}/.\t./.\t./admin", f"/proxy/{cid}/.\n./.\n./logout", f"/proxy/{cid}/.\r./logout",
                f"/proxy/{cid}/%2e\t%2e/logout", f"/proxy/{cid}/.\t./logout?x=1", f"/proxy/{cid}/ok\t",
                f"/proxy/{cid}/.%09./.%09./logout", f"/proxy/{cid}/.%0a./logout", f"/proxy/{cid}/.%0D./logout",
                f"/browser?connection={cid}&x=\n1"):
        check(f"E9: next={bad!r} falls back to the default", nxt(cid, bad) == default, nxt(cid, bad))
    for good in (f"/proxy/{cid}", f"/proxy/{cid}/", f"/proxy/{cid}/a..b/c", f"/proxy/{cid}/file.txt", f"/proxy/{cid}/page?q=../..",
                 f"/proxy/{cid}/https://other.example/x", f"/proxy/{cid}?a=1", f"/browser?connection={cid}&x=1",
                 f"/proxy/{cid}/x#../..", f"/browser?connection={cid}&q=../.."):
        check(f"E9: next={good!r} is kept", nxt(cid, good) == good, nxt(cid, good))
    check("E9: another connection or site still falls back", nxt(cid, "/proxy/other/x") == default and nxt(cid, "https://evil.example/") == default)

# (1.24.2, E36) A page request authenticated by ?token= to a shared connection whose notice is not accepted gets a
# plain 403 explanation, never a redirect to /shared-app (the notice page cannot see the token and would send the
# viewer to the sign-in page). The token is never copied into a Location header. A cookie session keeps the 302.
if nxt:
    import asyncio
    import aiohttp
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from grant_harness import boot, shutdown, check as hcheck  # noqa: E402

    async def notice_token_case():
        up = web.Application()
        up.router.add_get("/{tail:.*}", lambda r: web.Response(text="hello"))
        upstream = TestServer(up, host="127.0.0.1")
        await upstream.start_server()
        env = await boot(names=("owner", "carol"), superadmin=())
        try:
            async def no_resolve(host, port=0):
                return []
            _server.resolve_checked_host = no_resolve
            _server.resolve_checked_host_cached = no_resolve
            _server._SSRFSafeConnector = lambda ssl=None, **kw: aiohttp.TCPConnector(ssl=ssl)
            db = env.db
            uuid = await db.create_user_connection(env.uid["owner"], "shared-web", "http", "127.0.0.1", upstream.port, "{}")
            cid = (await (await db.conn.execute("SELECT id FROM user_connections WHERE uuid = ?", (uuid,))).fetchone())["id"]
            await db.add_connection_share(cid, env.uid["carol"], env.uid["owner"], None)
            jwt = [c.value for c in env.sessions["carol"].cookie_jar if c.key == _server.Config.SESSION_COOKIE_NAME][0]
            carol = env.sessions["carol"]
            doc = {"Accept": "text/html", "Sec-Fetch-Dest": "document"}
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as anon:
                async def tok(url, **kw):
                    async with anon.get(env.base + url, params={"token": jwt}, allow_redirects=False, headers=doc, **kw) as r:
                        return r.status, r.headers, (await r.read()).decode("utf-8", "replace")
                for url in (f"/proxy/{uuid}/page", f"/browser?connection={uuid}"):
                    st, hd, body = await tok(url)
                    hcheck(f"E36: ?token= on {url.split('?')[0].rsplit('/', 1)[-1] or url} to an unaccepted shared connection answers 403 with the explanation, no Location",
                           st == 403 and "Location" not in hd and "no-store" in hd.get("Cache-Control", "") and "private" in hd.get("Cache-Control", "")
                           and "This shared connection has not been opened yet. Sign in to the portal, open it once and choose Continue; "
                               "after that this address works." in body and jwt not in body and jwt not in str(dict(hd)),
                           f"{st} {hd.get('Location')} {body[:120]!r}")
            st, hd = None, None
            async with carol.get(f"{env.base}/proxy/{uuid}/page", allow_redirects=False, headers=doc) as r:
                await r.read()
                st, hd = r.status, r.headers
            hcheck("E36: a cookie page request to the same connection still gets the 302 to /shared-app",
                   st == 302 and hd.get("Location", "").startswith("/shared-app?connection=" + uuid), f"{st} {hd.get('Location')}")
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as anon:
                async with anon.get(f"{env.base}/proxy/{uuid}/data", params={"token": jwt}, allow_redirects=False,
                                    headers={"Sec-Fetch-Dest": "empty", "Accept": "*/*"}) as r:
                    await r.read()
                    hcheck("E36: a ?token= request that is not a page keeps the plain 403 (no Location)", r.status == 403 and "Location" not in r.headers, str(r.status))
            async with carol.post(f"{env.base}/api/connections/{uuid}/notice") as r:
                hcheck("E36: Continue is recorded through the cookie session", r.status == 200, str(r.status))
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as anon:
                st, hd, body = await tok_after(anon, env, uuid, jwt, doc)
                hcheck("E36: after the notice is accepted the same ?token= request passes (no 403 explanation, no /shared-app)",
                       "has not been opened yet" not in body and not hd.get("Location", "").startswith("/shared-app"), f"{st} {hd.get('Location')} {body[:80]!r}")
        finally:
            await shutdown(env)
            await upstream.close()

    async def tok_after(anon, env, uuid, jwt, doc):
        async with anon.get(f"{env.base}/proxy/{uuid}/page", params={"token": jwt}, allow_redirects=False, headers=doc) as r:
            return r.status, r.headers, (await r.read()).decode("utf-8", "replace")

    try:
        asyncio.run(asyncio.wait_for(notice_token_case(), 60))
    except Exception as exc:
        check("E36: the notice test ran to the end", False, repr(exc))
    failures.extend(f for f in __import__("grant_harness").failures if f not in failures)

if failures:
    print(f"\ntest_share_note_ui: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_share_note_ui: all checks passed")
