"""The Web Browser page (/rbrowser) and its admin card in a real Chromium, against the fake launcher (release 1.25.0).
Skipped without Chromium and Playwright (a failure with REQUIRE_BROWSER=1).

The portal runs as a child process on loopback (the app tests/grant_harness.py boots, with a temporary database), the
Web Browser switched on in stage mode with PORTAL_RBROWSER_FAKE=1: a session is a fake RFB server on a unix socket
(tests/fixtures/fake_rfb.py), no unit, no root, no real browser on the server side. The child also serves a tiny control
port on which the parent reads how many key and pointer messages the fake RFB server has received and how many sessions
exist. Only counts are ever read: no key code, pointer position, address, title or clipboard text is stored or printed.
Chromium (headless, with the offline flags of tools/make_screenshots.py) opens the page as an ordinary member at 1280x768
and at 390x844 with touch, and the admin card as a superadmin.

What it proves: the page loads with no console error and no content-security-policy violation; a session starts and the
noVNC canvas shows the fake server's picture (size and the colour of the fake's first rectangle); the toolbar buttons work
(Fit, Text, About, Quality, Keyboard focusing the hidden field, End with its question not under the opening click and
ignoring a click straight after it opens); text typed in the Keyboard field, sent from the text panel and pasted becomes key
events at the fake server; the text panel and the "Copy from the browser" button follow the clipboard setting (off, in, both)
and the received text is shown as text; a light and a dark theme change the page colours; ending removes the session;
the admin card loads, shows the running session without an address or title, saves a setting and shows it again after a reload.
It proves Chromium only and not a real remote browser, a real phone keyboard, or the picture quality.

Needs: Playwright importable in the interpreter that runs this file, /usr/bin/chromium (or $CHROMIUM), and a portal
interpreter for the child ($PORTAL_TEST_PYTHON, else ./venv/bin/python, else none).
Run: PLAYWRIGHT_BROWSERS_PATH=... REQUIRE_BROWSER=1 PORTAL_TEST_PYTHON=<venv>/bin/python <venv with playwright>/bin/python tests/test_rbrowser_page_browser.py
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
failures = []

FAKE_CLIP = "fake clipboard text"
# fake_rfb.RECT_PIXEL is the bytes 10 20 30 00. noVNC sets its own pixel format (red byte first) and the fake does not
# honour SetPixelFormat, so this is how noVNC reads those bytes; a real x11vnc honours it.
FAKE_RGB = (0x10, 0x20, 0x30)


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({str(detail)[:300]})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


# ---------------------------------------------------------------------------------------------------------
# Child: the portal with the Web Browser on and the fake launcher
# ---------------------------------------------------------------------------------------------------------

def serve():
    sys.path.insert(0, str(ROOT / "tests"))
    import asyncio
    import tempfile
    import grant_harness as h
    from grant_harness import server
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from config import Config
    import rbrowser

    facts = {"resolvers": [], "ifaces": [], "gateways": [], "gateways_scoped": []}

    async def main():
        env = await h.boot(names=("adm", "bob"), superadmin=("adm",))
        tmp = tempfile.mkdtemp(prefix="rbpage-")
        rbrowser.configure(environ={"PORTAL_RBROWSER_FAKE": "1"}, host_facts=lambda: facts, ncpu=4, mem_total=15 * 1024 ** 3,
                           cgroup_root=os.path.join(tmp, "cg"), tmp_dir=os.path.join(tmp, "tmp"), cache_path=os.path.join(tmp, "pf.json"))
        server._rbrowser_cfg.update(stage_mode=True, stage_dir=os.path.join(tmp, "stage"))
        os.makedirs(server._rbrowser_cfg["stage_dir"], exist_ok=True)
        async with env.sessions["adm"].put(f"{env.base}/api/admin/rbrowser",
                                           json={"rbrowser_enabled": True, "rbrowser_min_role": "user", "rbrowser_clipboard": "both"}) as r:
            ok = r.status == 200

        async def info(request):
            fakes = list(getattr(rbrowser.registry().launcher, "servers", {}).values())
            keys = sum(1 for f in fakes for t, _ in f.records if t == 4)
            pointers = sum(1 for f in fakes for t, _ in f.records if t == 5)
            return web.json_response({"keys": keys, "pointers": pointers, "sessions": len(rbrowser.all()), "attached": sum(1 for s in rbrowser.all() if s.viewer is not None)})
        app = web.Application()
        app.router.add_get("/info", info)
        ctl = TestServer(app, host="127.0.0.1")
        await ctl.start_server()
        cookies = {}
        for who, sess in env.sessions.items():
            cookies[who] = [c.value for c in sess.cookie_jar if c.key == Config.SESSION_COOKIE_NAME][0]
        print("READY " + json.dumps({"ok": ok, "base": env.base, "control": f"http://127.0.0.1:{ctl.port}", "cookies": cookies,
                                     "cookie_name": Config.SESSION_COOKIE_NAME}), flush=True)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, sys.stdin.readline)      # until the parent closes our stdin
        await ctl.close()
        await h.shutdown(env)

    h.run(main, 900)


# ---------------------------------------------------------------------------------------------------------
# Parent: Chromium
# ---------------------------------------------------------------------------------------------------------

OFFLINE_ARGS = [
    "--no-sandbox", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost",
    "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps",
    "--disable-field-trial-config", "--no-first-run", "--disable-domain-reliability", "--no-pings",
    "--disable-breakpad", "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update",
    "--no-proxy-server",
]

# Collected in every page before its own scripts run: content-security-policy violations, as the browser reports them.
INIT = """
window.__csp = [];
window.__wsclose = [];
(function () {
    var Orig = window.WebSocket;
    window.WebSocket = function (u, p) {
        var w = p === undefined ? new Orig(u) : new Orig(u, p);
        w.addEventListener('close', function (e) { window.__wsclose.push(e.code); });
        return w;
    };
    window.WebSocket.prototype = Orig.prototype;
    ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function (k) { window.WebSocket[k] = Orig[k]; });
})();
document.addEventListener('securitypolicyviolation', function (e) { window.__csp.push(e.violatedDirective + ' ' + e.blockedURI.slice(0, 40)); }, true);
"""


def get_json(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def wait_for(fn, seconds=15.0, step=0.15):
    end = time.time() + seconds
    while time.time() < end:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(step)
    return None


class Watch:
    """Console errors, page errors and CSP violations of one page."""

    def __init__(self, page):
        self.errors = []
        self.bad = []          # (path, status) of answers of 400 and above
        self.page = page
        # Chromium logs every failed fetch as "Failed to load resource": those are judged by the answers below instead
        page.on("console", lambda m: self.errors.append("console: " + m.text[:120])
                if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
        page.on("response", lambda r: self.bad.append((r.url.split("?")[0].replace(page.url.split("/rbrowser")[0], ""), r.status)) if r.status >= 400 else None)
        page.on("pageerror", lambda e: self.errors.append("pageerror: " + str(e)[:120]))

    def csp(self):
        try:
            return self.page.evaluate("window.__csp || []")
        except Exception:
            return []


def dismiss_tour(page):
    """The first-visit welcome dialog of the admin page covers the card."""
    wait_for(lambda: page.evaluate("!!(window.Portal && Portal.welcomeTour)"), 10)
    page.evaluate("window.Portal && Portal.welcomeTour && Portal.welcomeTour.dismiss && Portal.welcomeTour.dismiss()")


def luminance(rgb):
    r, g, b = (int(x) for x in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def parse_rgb(text):
    import re
    m = re.findall(r"[\d.]+", text)
    return [float(x) for x in m[:3]] if len(m) >= 3 else [0, 0, 0]


def run_browser(info):
    from playwright.sync_api import sync_playwright
    base, control = info["base"], info["control"]
    chromium = os.environ.get("CHROMIUM", "/usr/bin/chromium")

    def counts():
        return get_json(control + "/info")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chromium, headless=True, args=OFFLINE_ARGS)

        def ctx_for(who, **kw):
            ctx = browser.new_context(**kw)
            ctx.add_cookies([{"name": info["cookie_name"], "value": info["cookies"][who], "url": base, "httpOnly": True, "sameSite": "Lax"}])
            ctx.add_init_script(INIT)
            return ctx

        adm_ctx = ctx_for("adm", viewport={"width": 1280, "height": 768})
        adm_api = adm_ctx.request

        def put_settings(body):
            r = adm_api.put(base + "/api/admin/rbrowser", data=body)
            return r.status

        def open_page(ctx, label):
            page = ctx.new_page()
            watch = Watch(page)
            page.goto(base + "/rbrowser")
            return page, watch

        def wait_connected(page, label):
            ok = wait_for(lambda: page.locator("#rb-status-text").inner_text() == "Connected" and page.locator("#rb-end").is_visible()
                          and page.locator("#rb-screen canvas").count() > 0, 20)
            check(f"{label}: a session starts, the page says Connected and shows the canvas and the End button", bool(ok))
            return bool(ok)

        def picture(page, label):
            """The canvas size and the colour of the fake's first rectangle against a pixel outside it."""
            res = wait_for(lambda: page.evaluate("""() => {
                const c = document.querySelector('#rb-screen canvas');
                if (!c || !c.width) return null;
                const g = c.getContext('2d');
                const a = g.getImageData(1, 1, 1, 1).data, b = g.getImageData(100, 100, 1, 1).data;
                return {w: c.width, h: c.height, a: [a[0], a[1], a[2]], b: [b[0], b[1], b[2]]};
            }"""), 15)
            if res and tuple(res["a"]) != FAKE_RGB:       # the first update may not have been painted yet
                res = wait_for(lambda: (lambda r: r if r and tuple(r["a"]) == FAKE_RGB else None)(page.evaluate("""() => {
                    const c = document.querySelector('#rb-screen canvas'); const g = c.getContext('2d');
                    const a = g.getImageData(1, 1, 1, 1).data, b = g.getImageData(100, 100, 1, 1).data;
                    return {w: c.width, h: c.height, a: [a[0], a[1], a[2]], b: [b[0], b[1], b[2]]};
                }""")), 10) or res
            check(f"{label}: the canvas is the fake server's 800x600 picture", bool(res) and (res["w"], res["h"]) == (800, 600), res)
            check(f"{label}: the fake's first rectangle is drawn in its colour and the rest of the canvas is not",
                  bool(res) and tuple(res["a"]) == FAKE_RGB and tuple(res["b"]) != FAKE_RGB, res)

        def clean(page, watch, label):
            check(f"{label}: no content-security-policy violation", watch.csp() == [], watch.csp())
            check(f"{label}: no console error and no page error", watch.errors == [], watch.errors)
            check(f"{label}: the only failed request is the page's first look for a session (404 before it starts one)",
                  set(watch.bad) <= {("/api/rbrowser/session", 404)}, watch.bad)

        def end_session(page, label, desktop):
            """The End button opens a question whose confirm button is not under the opening click, ignores a click
            straight after it opens, and ends the session after the delay."""
            box = page.locator("#rb-end").bounding_box()
            cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
            page.locator("#rb-end").click()
            ok = wait_for(lambda: page.locator("#rb-end-yes").is_visible(), 5)
            check(f"{label}: End opens a question", bool(ok))
            yes = page.locator("#rb-end-yes").bounding_box()
            under = yes and yes["x"] <= cx <= yes["x"] + yes["width"] and yes["y"] <= cy <= yes["y"] + yes["height"]
            check(f"{label}: the question's confirm button is not under the click that opened it", bool(yes) and not under, f"{box} {yes}")
            page.evaluate("document.getElementById('rb-end-yes').click()")      # a click with no pointer, straight after it opened
            time.sleep(0.2)
            check(f"{label}: a confirm click in the first moments is ignored (question still open, session still there)",
                  page.locator("#rb-end-yes").is_visible() and counts()["sessions"] >= 1)
            page.locator("#rb-end-no").click()
            check(f"{label}: Keep it closes the question and keeps the session", wait_for(lambda: not page.locator("#rb-end-yes").is_visible(), 3) and counts()["sessions"] >= 1)
            page.locator("#rb-end").click()
            time.sleep(0.8)
            page.locator("#rb-end-yes").click()
            gone = wait_for(lambda: counts()["sessions"] == 0, 10)
            check(f"{label}: confirming ends the session at the server", bool(gone), counts())
            shown = wait_for(lambda: page.locator("#rb-overlay").is_visible() and not page.locator("#rb-end").is_visible(), 5)
            check(f"{label}: the page says it ended and offers no End button", bool(shown))

        # ------------------------------------------------------------------ 1. desktop, clipboard both ways
        check("the admin switched the feature on in the child", info["ok"])
        ctx = ctx_for("bob", viewport={"width": 1280, "height": 768})
        page, watch = open_page(ctx, "desktop")
        L = "desktop (both ways)"
        if wait_connected(page, L):
            picture(page, L)
            check(f"{L}: one viewer is attached at the server", wait_for(lambda: counts()["attached"] == 1, 5))
            # toolbar
            vis = {i: page.locator("#" + i).is_visible() for i in ("rb-dashboard", "rb-keyboard", "rb-text-toggle", "rb-quality-wrap", "rb-fit", "rb-about", "rb-end")}
            check(f"{L}: the toolbar shows Dashboard, Keyboard, Text, Quality, Fit, About and End", all(vis.values()), vis)
            tb = page.evaluate("(() => { const t = document.getElementById('rb-toolbar'); const r = t.getBoundingClientRect(); return [r.width, t.scrollWidth]; })()")
            check(f"{L}: the toolbar fits the width (no sideways scroll)", tb[1] <= tb[0] + 1, tb)
            page.locator("#rb-fit").click()
            check(f"{L}: Fit toggles to 1:1 and back", page.locator("#rb-fit").inner_text().strip() == "1:1"
                  and (page.locator("#rb-fit").click() or True) and page.locator("#rb-fit").inner_text().strip() == "Fit")
            page.select_option("#rb-quality", "sharp")
            check(f"{L}: Quality is remembered in the page's own storage", page.evaluate("localStorage.getItem('rbrowser.quality')") == "sharp")
            page.locator("#rb-about").click()
            about = page.locator("#rb-about-panel")
            check(f"{L}: About shows the privacy statement and the limits", about.is_visible()
                  and page.locator("#rb-privacy").inner_text().startswith("The Web Browser runs on the server, not on your device.")
                  and page.locator("#rb-limits li").count() >= 8)
            page.locator("#rb-about-close").click()
            check(f"{L}: About closes", not about.is_visible())
            # the text panel follows the clipboard setting: both
            page.locator("#rb-text-toggle").click()
            check(f"{L}: Text opens the panel with Send text and Copy from the browser", page.locator("#rb-textpanel").is_visible()
                  and page.locator("#rb-send-text").is_visible() and page.locator("#rb-get-clip").is_visible())
            k0 = counts()["keys"]
            page.fill("#rb-textbox", "hi")
            page.locator("#rb-send-text").click()
            moved = wait_for(lambda: counts()["keys"] - k0 >= 4, 10)
            check(f"{L}: Send text becomes key events at the fake server (2 characters, press and release) and empties the box",
                  bool(moved) and page.input_value("#rb-textbox") == "", f"{counts()['keys'] - k0}")
            page.locator("#rb-get-clip").click()
            got = wait_for(lambda: page.locator("#rb-received").inner_text() == FAKE_CLIP, 8)
            check(f"{L}: Copy from the browser shows the remote text in the box", bool(got) and page.locator("#rb-received-wrap").is_visible())
            check(f"{L}: the received text went in as text, not markup", page.evaluate("document.getElementById('rb-received').children.length") == 0)
            # a paste event outside the fields is typed
            page.locator("#rb-textpanel").evaluate("e => e.hidden = true")
            k0 = counts()["keys"]
            page.evaluate("""() => { const dt = new DataTransfer(); dt.setData('text/plain', 'abc');
                document.body.dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true})); }""")
            moved = wait_for(lambda: counts()["keys"] - k0 >= 6, 10)
            check(f"{L}: a paste event becomes key events (3 characters)", bool(moved), f"{counts()['keys'] - k0}")
            # the keyboard button focuses the hidden field; typing in it reaches the server
            page.locator("#rb-keyboard").click()
            check(f"{L}: Keyboard focuses the hidden input field", page.evaluate("document.activeElement && document.activeElement.id") == "rb-kbd")
            k0 = counts()["keys"]
            page.keyboard.type("ok")
            moved = wait_for(lambda: counts()["keys"] - k0 >= 4, 10)
            check(f"{L}: characters typed there become key events", bool(moved), f"{counts()['keys'] - k0}")
            check(f"{L}: and the field is emptied again", wait_for(lambda: page.input_value("#rb-kbd") == "", 3))
            # themes
            def tb_colours():
                return page.evaluate("""() => { const s = getComputedStyle(document.getElementById('rb-toolbar'));
                    return [s.backgroundColor, s.color]; }""")
            page.evaluate("ThemeSwitcher.apply('dark')")
            dark = tb_colours()
            page.evaluate("ThemeSwitcher.apply('light')")
            light = tb_colours()
            check(f"{L}: a light and a dark theme change the toolbar colours (light is lighter)",
                  light != dark and luminance(parse_rgb(light[0])) > luminance(parse_rgb(dark[0])) + 40, f"{dark} {light}")
            page.evaluate("ThemeSwitcher.apply('dark')")
            # the admin card, while the session runs
            apage = adm_ctx.new_page()
            awatch = Watch(apage)
            apage.goto(base + "/admin")
            dismiss_tour(apage)
            apage.evaluate("showTab('settings', null)")
            shown_card = wait_for(lambda: apage.locator("#rbrowser-admin-card").is_visible(), 20)
            check("admin: the Web Browser card loads", bool(shown_card))
            if shown_card:
                row = wait_for(lambda: apage.locator("#rbrowser-admin-sessions tr").count() >= 1 and apage.locator("#rbrowser-admin-sessions").inner_text() or None, 15)
                text = apage.locator("#rbrowser-admin-sessions").inner_text()
                check("admin: the running session is listed with the member and no address", bool(row) and "bob" in text and "http" not in text.lower(), text[:80])
                check("admin: the availability text says the server can run it", "can run the browser" in apage.locator("#rbrowser-admin-avail").inner_text())
                apage.fill("#rbrowser-set-rbrowser_idle_minutes", "20")
                apage.locator(".rbrowser-admin-save").click()
                saved = wait_for(lambda: "Saved" in apage.locator("#rbrowser-admin-note").inner_text(), 10)
                check("admin: Save settings saves a changed setting", bool(saved), apage.locator("#rbrowser-admin-note").inner_text())
                apage.reload()
                dismiss_tour(apage)
                apage.evaluate("showTab('settings', null)")
                wait_for(lambda: apage.locator("#rbrowser-admin-card").is_visible(), 20)
                wait_for(lambda: apage.locator("#rbrowser-set-rbrowser_idle_minutes").count() == 1, 10)
                check("admin: the saved value is there after a reload", apage.input_value("#rbrowser-set-rbrowser_idle_minutes") == "20")
                apage.fill("#rbrowser-set-rbrowser_idle_minutes", "15")
                apage.locator(".rbrowser-admin-save").click()
                wait_for(lambda: "Saved" in apage.locator("#rbrowser-admin-note").inner_text(), 10)
            check("admin page: no content-security-policy violation", awatch.csp() == [], awatch.csp())
            check("admin page: no console error from the card", [e for e in awatch.errors if "rbrowser" in e.lower()] == [], awatch.errors)
            apage.close()
            clean(page, watch, L)
            end_session(page, L, True)
        page.close()
        ctx.close()

        # ------------------------------------------------------------------ 2. phone, clipboard into the browser only
        L = "phone 390x844 (in only)"
        check(f"{L}: the setting is changed to in", put_settings({"rbrowser_clipboard": "in"}) == 200)
        ctx = ctx_for("bob", viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True, device_scale_factor=2)
        page, watch = open_page(ctx, L)
        if wait_connected(page, L):
            picture(page, L)
            tb = page.evaluate("(() => { const t = document.getElementById('rb-toolbar'); const r = t.getBoundingClientRect(); return [r.width, t.scrollWidth, document.documentElement.scrollWidth, innerWidth]; })()")
            check(f"{L}: the toolbar and the page fit the phone width", tb[1] <= tb[0] + 1 and tb[2] <= tb[3] + 1, tb)
            check(f"{L}: Keyboard and End are on the toolbar", page.locator("#rb-keyboard").is_visible() and page.locator("#rb-end").is_visible())
            page.locator("#rb-keyboard").tap()
            check(f"{L}: Keyboard focuses the hidden input field", page.evaluate("document.activeElement && document.activeElement.id") == "rb-kbd")
            k0 = counts()["keys"]
            page.keyboard.type("hello")
            moved = wait_for(lambda: counts()["keys"] - k0 >= 10, 10)
            check(f"{L}: text typed on the phone keyboard path becomes key events at the fake server", bool(moved), f"{counts()['keys'] - k0}")
            page.locator("#rb-text-toggle").tap()
            check(f"{L}: with in only the text panel opens and there is no Copy from the browser", page.locator("#rb-textpanel").is_visible()
                  and page.locator("#rb-send-text").is_visible() and not page.locator("#rb-get-clip").is_visible())
            panel = page.locator("#rb-textpanel").bounding_box()
            check(f"{L}: the text panel lies inside the screen", bool(panel) and panel["x"] >= -1 and panel["x"] + panel["width"] <= 391, panel)
            clean(page, watch, L)
            end_session(page, L, False)
        page.close()
        ctx.close()

        # ------------------------------------------------------------------ 3. desktop, clipboard off
        L = "desktop (clipboard off)"
        check(f"{L}: the setting is changed to off", put_settings({"rbrowser_clipboard": "off"}) == 200)
        ctx = ctx_for("bob", viewport={"width": 1280, "height": 768})
        page, watch = open_page(ctx, L)
        if wait_connected(page, L):
            check(f"{L}: there is no Text button, no panel and no Copy from the browser", not page.locator("#rb-text-toggle").is_visible()
                  and not page.locator("#rb-textpanel").is_visible() and not page.locator("#rb-get-clip").is_visible())
            k0 = counts()["keys"]
            page.evaluate("""() => { const dt = new DataTransfer(); dt.setData('text/plain', 'abc');
                document.body.dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true})); }""")
            time.sleep(1.0)
            check(f"{L}: a paste event is not typed", counts()["keys"] == k0, f"{counts()['keys'] - k0}")
            page.locator("#rb-keyboard").click()
            k0 = counts()["keys"]
            page.keyboard.press("Enter")
            check(f"{L}: typing with the keyboard still works", bool(wait_for(lambda: counts()["keys"] - k0 >= 2, 8)))
            clean(page, watch, L)
            r = page.evaluate("fetch('/api/rbrowser/session/clipboard', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'}).then(r => r.status)")
            check(f"{L}: the clipboard route answers 403", r == 403, r)
        page.close()
        ctx.close()
        put_settings({"rbrowser_clipboard": "both"})

        # ------------------------------------------------------------------ 4. a second window of the same member
        L = "desktop (a second window)"
        ctx = ctx_for("bob", viewport={"width": 1280, "height": 768})
        p1, w1 = open_page(ctx, L)
        if wait_connected(p1, L):
            p2, w2 = open_page(ctx, L)
            # Which of the two windows wins is not pinned here: the replaced window is told 4012 (and stays quiet), but now and then
            # it sees an abnormal close (1006) instead, reconnects and takes the session back, so the windows swap places (see the
            # report of this test: the old handler returns while the new attach is still closing its socket). Either way exactly one
            # window shows the picture, the other says it is open elsewhere, and the server has one session with one viewer.
            def roles():
                st = [p.locator("#rb-status-text").inner_text() for p in (p1, p2)]
                return st if sorted(st) == ["Connected", "Open in another window"] else None
            settled = wait_for(roles, 20)
            check(f"{L}: one window is Connected and the other says it is open in another window", bool(settled), settled)
            check(f"{L}: the server has one session and one viewer", wait_for(lambda: counts()["sessions"] == 1 and counts()["attached"] == 1, 5))
            live = p1 if settled and settled[0] == "Connected" else p2
            try:
                end_session(live, L, True)
            except Exception as e:
                check(f"{L}: the connected window ends the session", False, repr(e))
            p2.close()
        p1.close()
        ctx.close()
        adm_ctx.close()
        browser.close()


def skip(reason):
    """No browser run is possible here. Exit 0 with a "skip:" line, unless REQUIRE_BROWSER=1 is set (the release
    checklist sets it): then this is a failure with exit code 3, so a skipped run is never read as a pass."""
    if os.environ.get("REQUIRE_BROWSER") == "1":
        print(f"FAIL: REQUIRE_BROWSER=1 and this run would skip: {reason}")
        sys.exit(3)
    print("skip: " + reason)


def main():
    if "--serve" in sys.argv:
        serve()
        return
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        skip("Playwright is not importable here")
        return
    if not Path(os.environ.get("CHROMIUM", "/usr/bin/chromium")).exists():
        skip("no Chromium")
        return
    py = os.environ.get("PORTAL_TEST_PYTHON") or (str(ROOT / "venv" / "bin" / "python") if (ROOT / "venv" / "bin" / "python").exists() else "")
    if not py:
        skip("no portal interpreter (set PORTAL_TEST_PYTHON)")
        return
    child = subprocess.Popen([py, "-B", __file__, "--serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        deadline = time.time() + 90
        info = None
        while time.time() < deadline:
            line = child.stdout.readline()
            if line.startswith("READY "):
                info = json.loads(line[6:])
                break
            if not line and child.poll() is not None:
                break
        check("the portal child started", info is not None)
        threading.Thread(target=lambda: [None for _ in child.stdout], daemon=True).start()    # keep the pipe drained
        if info:
            run_browser(info)
    finally:
        try:
            child.stdin.close()
            child.wait(timeout=15)
        except Exception:
            child.kill()
    if failures:
        print(f"\ntest_rbrowser_page_browser: {len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print("\ntest_rbrowser_page_browser: all checks passed")


main()
