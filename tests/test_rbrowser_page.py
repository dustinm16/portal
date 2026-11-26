"""The Web Browser page (static/rbrowser.html, static/js/rbrowser.js, static/css/rbrowser.css), the admin card
(static/js/rbrowser-admin.js and its markup in admin.html) and the dashboard card (loadRbrowserCard in dashboard.js).

Source checks (no inline script and no inline handler, because the route has its own strict policy; every id the
script uses exists in the page; the privacy statement and the limits text; no innerHTML; no hard-coded colour; no
emoji) and the script itself under Node (tests/rbrowser_page_harness.js): the state machine, the close codes, the
reconnect timing, takeover, the boot id, the warnings, resize, typing, paste, the phone keyboard and the clipboard.
No browser: layout, a real noVNC, a real phone keyboard and a real clipboard are not proven here (Lane D's browser
test and the release gate cover them).

Run: venv/bin/python tests/test_rbrowser_page.py
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
failed = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failed.append(name)


HTML = (STATIC / "rbrowser.html").read_text(encoding="utf-8")
JS = (STATIC / "js" / "rbrowser.js").read_text(encoding="utf-8")
CSS = (STATIC / "css" / "rbrowser.css").read_text(encoding="utf-8")


def squash(text):
    return re.sub(r"\s+", " ", text).strip()


# ---- the page's markup ----
scripts = re.findall(r"<script\b([^>]*)>", HTML, re.I)
check("the page has scripts", len(scripts) >= 3, str(scripts))
check("every script tag has a src (no inline script: the route policy forbids it)",
      all(re.search(r"\bsrc=", a) for a in scripts), str(scripts))
check("no script tag has a body", not re.search(r"<script\b[^>]*>\s*[^<\s]", HTML, re.I))
check("no on*= attribute anywhere in the page", not re.search(r"<[^>]+\son[a-z]+\s*=", HTML, re.I))
check("no javascript: address", "javascript:" not in HTML.lower())
check("no {{placeholder}} (the page is served as it is)", "{{" not in HTML)
check("no inline style attribute", not re.search(r"<[^>]+\sstyle\s*=", HTML, re.I))
check("the theme script is in the head, before the body, as vnc.html has it",
      HTML.index("/static/js/theme.js?v=3") < HTML.index("<body"))
check("the module script is rbrowser.js with a version",
      '<script type="module" src="/static/js/rbrowser.js?v=2"></script>' in HTML)
check("portal.css keeps its version and the page's own rules come from rbrowser.css",
      "/static/css/portal.css?v=56" in HTML and "/static/css/rbrowser.css?v=2" in HTML)
check("portal.js is loaded as a classic script before the module", HTML.index("/static/js/portal.js?v=52") < HTML.index("rbrowser.js"))
check("the page is not indexed", 'name="robots" content="noindex, nofollow"' in HTML)
check("no sign-out link (it would pull in the push script)", 'href="/logout"' not in HTML)
check("the page does not load anything from another host", not re.search(r"""(?:src|href)=["'](?:https?:)?//""", HTML))

head, body = HTML.split("<body", 1)
toolbar = body[body.index('<header class="rb-toolbar"'): body.index("</header>")]
check("the End confirmation is not inside the toolbar that holds the End button",
      'id="rb-end"' in toolbar and 'id="rb-confirm"' not in toolbar and 'id="rb-end-yes"' not in toolbar)
check("the Dashboard link, the status and the Keyboard, Quality, Fit, Fullscreen and End controls exist",
      all(i in toolbar for i in ('id="rb-dashboard"', 'id="rb-status"', 'id="rb-keyboard"', 'id="rb-quality"', 'id="rb-fit"', 'id="rb-fullscreen"', 'id="rb-end"')))
check("the Dashboard link goes to /", re.search(r'<a [^>]*id="rb-dashboard"[^>]*href="/"', HTML) is not None)

ids = set(re.findall(r'\sid="([^"]+)"', HTML))
check("ids in the page are unique", len(re.findall(r'\sid="([^"]+)"', HTML)) == len(ids))
used = set(re.findall(r"'(rb-[a-z0-9-]+)'", JS))
check("the script uses ids", len(used) > 30, str(len(used)))
check("every id the script uses is in the page", used <= ids, str(sorted(used - ids)))

# ---- the privacy statement (section 14, verbatim) and the limits ----
STATEMENT = (
    "The Web Browser runs on the server, not on your device. Websites see the server's address, not yours. "
    "The portal has no function that records, logs or stores the addresses you open, what you type, or what "
    "is on the screen, and it keeps no history: the browser's profile lives in memory and is destroyed when "
    "the session ends. The portal does log that you started and ended a session, when, and how much data it "
    "moved; administrators can see that you have a session and whether it is active. This is not protection "
    "from the people who run this portal: its administrators have full access to the server and could "
    "observe a running browser there, including sites you are signed in to. The picture of the browser "
    "travels through the portal process and through Cloudflare's network like every other page of the portal "
    "(encrypted in transit, readable at those two points). Name lookups go to a DNS-over-HTTPS resolver "
    "(Cloudflare's 1.1.1.1), which sees the names of the sites opened from the server. Do not use it for "
    "anything you would not open on a computer that belongs to someone else."
)
m = re.search(r'<p id="rb-privacy">(.*?)</p>', HTML, re.S)
check("the About panel has the privacy statement, word for word", m is not None and squash(m.group(1)) == STATEMENT,
      squash(m.group(1))[:200] if m else "no paragraph")
check("the statement names administrators and the DNS resolver", "its administrators have full access to the server" in HTML and "DNS-over-HTTPS" in HTML)
lim = re.search(r'<ol id="rb-limits">(.*?)</ol>', HTML, re.S)
items = re.findall(r"<li>(.*?)</li>", lim.group(1), re.S) if lim else []
check("the limits list has the seven items of the design and the dead-key item", len(items) == 8, str(len(items)))
for phrase in ("video of a browser", "No sound", "Copy from the browser", "server's address", "Limited seats", "Ctrl+W", "Chinese, Japanese and Korean"):
    check(f"the limits list says: {phrase}", any(phrase in squash(i) for i in items))
check("the limits list says dead keys do not compose and to type the finished character",
      any("dead keys do not compose; type the finished character" in squash(i).lower().replace(".", "") for i in items))
check("the limits list no longer says copying out is Latin-1 only", "Latin-1" not in HTML)
check("the limits list adds no scroll-rate or timeout limit (only the dead-key limit was asked for)",
      "frames a second" not in HTML and "times out" not in HTML)
check("the page says nothing inside the picture can be themed", "portal themes do not change it" in HTML)

# ---- the script's source ----
check("the module's first line is the noVNC import as vnc.html writes it",
      JS.startswith("import RFB from '/static/vendor/novnc/core/rfb.js?v=1.4.0';\n"))
first_fn = JS.index("function ")
for const in ("MIN_W = 560", "QUALITY_LEVELS = [", "DEFAULT_QUALITY = 'balanced'", "TYPE_CHUNK = 40", "TYPE_INTERVAL_MS = 30", "TYPE_MAX_CHARS = 5000"):
    check(f"constant at the top, before any function: {const}", 0 <= JS.find("const " + const) < first_fn)
check("exactly three quality pairs with noVNC levels in range",
      len(re.findall(r"\{ id: '[a-z]+', label: '[A-Za-z]+', quality: \d, compression: \d \}", JS)) == 3)
check("no innerHTML, outerHTML, insertAdjacentHTML, document.write, eval or Function constructor in the script",
      not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function", JS))
check("no inline handler property or attribute is set by the script", not re.search(r"\.on(click|input|change|keydown)\s*=|setAttribute\(\s*['\"]on", JS))
check("the script never logs (typed and copied text must not reach a console)", "console." not in JS)
check("server and remote text goes in with textContent", "textContent" in JS and "createTextNode" not in JS)
check("the script does not store text or keys: the only storage keys are the quality and the boot id",
      sorted(set(re.findall(r"'(rbrowser\.[a-z]+)'", JS))) == ["rbrowser.boot", "rbrowser.quality"])
SCRIPT_CODE = re.sub(r"/\*.*?\*/", "", JS, flags=re.S)
SCRIPT_CODE = re.sub(r"(?m)^\s*//.*$", "", SCRIPT_CODE)
check("the VNC clipboard is not used: no clipboardPasteFrom, no noVNC 'clipboard' listener",
      "clipboardPasteFrom" not in SCRIPT_CODE and not re.search(r"addEventListener\(\s*'clipboard'", SCRIPT_CODE))
check("Put on the remote clipboard is gone from the page and the script",
      "Put on the remote clipboard" not in HTML + JS and "rb-put-clip" not in HTML + JS and "rb-clip-hint" not in HTML + JS)
check("the page has a Copy from the browser button, hidden until the mode is both, and the route it calls",
      re.search(r'<button[^>]*id="rb-get-clip"[^>]*hidden[^>]*>Copy from the browser</button>', HTML) is not None
      and "'/api/rbrowser/session/clipboard'" in JS and "show('rb-get-clip', clipMode === 'both')" in JS)
check("the received text goes in through textContent and the page never logs or stores it",
      "setText('rb-received', received)" in JS and "storeSet(" not in JS[JS.index("async function copyFromBrowser"):JS.index("async function copyReceived")])
check("storage is only touched inside try/catch", all(
    re.search(r"try \{[^}]*" + fn, JS) for fn in (r"env\.storage\.getItem", r"env\.storage\.setItem", r"env\.storage\.removeItem")))
check("the paste key handler uses the capture phase on the document and does not cancel the key",
      "doc.addEventListener('keydown', onKeydownCapture, true)" in JS
      and "e.stopPropagation();" in JS[JS.index("function onKeydownCapture"): JS.index("function onPaste")]
      and "preventDefault" not in JS[JS.index("function onKeydownCapture"): JS.index("function onPaste")])
check("the idle control frame is exactly {op: here} as a text frame", "ws.send(JSON.stringify({ op: 'here' }))" in JS)
check("reconnect is only for 1006 and 1001, with the delays 1 s, 2 s, 5 s",
      "RECONNECT_CODES = [1006, 1001]" in JS and "RECONNECT_DELAYS_MS = [1000, 2000, 5000]" in JS)
check("the clamp uses the 560 x 480 minimum, 1920 x 1200 maximum and multiples of 16",
      "MIN_W = 560" in JS and "MIN_H = 480" in JS and "MAX_W = 1920" in JS and "MAX_H = 1200" in JS and "SNAP = 16" in JS)
check("resize is debounced for 500 ms and scaling is on", "RESIZE_DEBOUNCE_MS = 500" in JS and "scaleViewport = fit" in JS and "resizeSession = false" in JS)

# ---- style: variables only, no emoji ----
check("the stylesheet uses no hard-coded colour", not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", CSS))
check("the stylesheet uses the portal's variables", all(v in CSS for v in ("var(--bg-secondary)", "var(--card-border)", "var(--text-primary)")))

# The toolbar on a phone (about 390px): it wraps instead of scrolling the privacy statement and End session out of
# sight, and the way back, About and End come first. Layout itself is Lane D's browser test (End and About inside
# the 390x844 viewport); this pins the rules that make it so.
PHONE = CSS[CSS.index("@media (max-width: 640px)"):]
check("phone: the toolbar wraps and does not scroll sideways", re.search(r"\.rb-toolbar\s*\{[^}]*flex-wrap:\s*wrap", PHONE) and re.search(r"\.rb-toolbar\s*\{[^}]*overflow-x:\s*visible", PHONE))
check("phone: Dashboard, About and End session are ordered ahead of everything else",
      re.search(r"\.rb-toolbar\s*>\s*\*\s*\{[^}]*order:\s*5", PHONE)
      and all(re.search(r"#" + i + r"\s*\{[^}]*order:\s*" + o, PHONE) for i, o in (("rb-dashboard", "1"), ("rb-about", "2"), ("rb-end", "3"))))
check("phone: the long part of the About label is dropped", ".rb-long" in PHONE and 'About<span class="rb-long"> this browser</span>' in HTML)
check("a refusal has a banner on the picture as well as the line in the text panel",
      'id="rb-banner-msg"' in HTML and HTML.index('id="rb-banner-msg"') < HTML.index('id="rb-textpanel"') and "rb-banner-msg" in JS)
EMOJI = re.compile("[\U0001F000-\U0001FAFF☀-➿⬀-⯿️‍]")
for name, text in (("rbrowser.html", HTML), ("rbrowser.js", JS), ("rbrowser.css", CSS)):
    check(f"no emoji in {name}", not EMOJI.search(text))

# ---- the admin card, the dashboard card and the skip lists: source checks ----
ADMIN_JS = (STATIC / "js" / "rbrowser-admin.js").read_text(encoding="utf-8")
ADMIN_HTML = (STATIC / "admin.html").read_text(encoding="utf-8")
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
DASH = (STATIC / "js" / "dashboard.js").read_text(encoding="utf-8")
SW = (STATIC / "sw.js").read_text(encoding="utf-8")

check("admin: the script never uses innerHTML, outerHTML, insertAdjacentHTML, document.write or eval",
      not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function", ADMIN_JS))
check("admin: no inline handler is set and nothing is logged", not re.search(r"\.on(click|input|change)\s*=|setAttribute\(\s*['\"]on", ADMIN_JS) and "console." not in ADMIN_JS)
check("admin: the script reads no web address, title or picture from a session (and the card has no input for one)",
      not re.search(r"\.(url|title|screenshot|picture)\b", re.sub(r"/\*.*?\*/", "", ADMIN_JS, flags=re.S))
      and not re.search(r"rbrowser-admin[^>]*>.*?type=\"url\"", ADMIN_HTML[ADMIN_HTML.index('id="rbrowser-admin-card"'):ADMIN_HTML.index("Certificate Management Card")], re.S))
check("admin: the session fields it reads are the documented ones",
      "SESSION_FIELDS = ['sid_prefix', 'user_id', 'username', 'started', 'state', 'attached', 'memory_mb', 'cpu_seconds', 'net_in_mb', 'net_out_mb']" in ADMIN_JS)
check("admin: the ten settings of section 8.1 are all in the form",
      all(f"key: 'rbrowser_{k}'" in ADMIN_JS for k in ("enabled", "min_role", "max_sessions", "idle_minutes", "memory_mb", "cpu_percent", "clipboard", "home_url", "upload_kbps", "extra_deny"))
      and len(re.findall(r"\{ key: 'rbrowser_", ADMIN_JS)) == 10)
check("admin: the End question waits 600 ms", "CONFIRM_DELAY_MS = 600" in ADMIN_JS)
check("admin.html loads rbrowser-admin.js with a version, after the other admin card scripts",
      re.search(r'<script src="/static/js/rbrowser-admin\.js\?v=1"></script>', ADMIN_HTML) is not None
      and ADMIN_HTML.index('<script src="/static/js/rbrowser-admin.js') > ADMIN_HTML.index('<script src="/static/js/block-ref-admin.js'))
card_ids = ("rbrowser-admin-card", "rbrowser-admin-note", "rbrowser-admin-avail", "rbrowser-admin-checks", "rbrowser-admin-settings", "rbrowser-admin-seats", "rbrowser-admin-sessions")
check("admin.html has the card and every id the script reads, and the card starts hidden",
      all(f'id="{i}"' in ADMIN_HTML for i in card_ids) and re.search(r'id="rbrowser-admin-card" style="display:none;', ADMIN_HTML) is not None
      and all(f"getElementById('{i}')" in ADMIN_JS for i in card_ids))
check("the card says the portal keeps no address, title, keystroke or picture", "keeps no address, page title, keystroke or picture" in ADMIN_HTML)
sec = re.search(r"const SEC_EVENTS = \[(.*?)\];", ADMIN_HTML, re.S).group(1)
names = ("rbrowser_settings_changed", "rbrowser_preflight_failed", "rbrowser_listener_found", "rbrowser_socket_mismatch",
         "rbrowser_display_mismatch", "rbrowser_protocol_violation", "rbrowser_traffic_limit")
check("SEC_EVENTS has the seven new names of section 5.5 and no others of this feature",
      all(f"'{n}'" in sec for n in names) and sorted(re.findall(r"'(rbrowser_[a-z_]+)'", sec)) == sorted(names))
check("the dashboard card has its own slot in My Connections, hidden, outside the connection grid",
      re.search(r'<div id="rbrowser-card-slot" hidden', INDEX) is not None
      and INDEX.index('id="rbrowser-card-slot"') < INDEX.index('id="inline-connections-grid"')
      and INDEX.index('id="rbrowser-card-slot"') > INDEX.index('id="tab-my-connections"'))
check("the dashboard asks GET /api/rbrowser/status and draws only for allowed === true",
      "Portal.fetch('/api/rbrowser/status')" in DASH and "status.allowed !== true" in DASH and "loadRbrowserCard();" in DASH)
fn = DASH[DASH.index("async function loadRbrowserCard"):]
fn = fn[:fn.index("\n}\n")]
check("the dashboard card is built with textContent, no innerHTML, no toast, no console", "innerHTML" not in fn and "Portal.toast" not in fn and "console." not in fn and "textContent" in fn)
check("the dashboard script is loaded at version 62", 'dashboard.js?v=62"' in INDEX)
check("sw.js never takes a tap to an open /rbrowser window", "u.pathname !== '/browser' && u.pathname !== '/rbrowser'" in SW)
check("rbrowser.html loads neither push.js nor the manifest (nothing to register there)", "push.js" not in HTML and "manifest" not in HTML)

# ---- the script under Node ----
node = shutil.which("node")
if not node:
    check("node is installed", False, "node not found")
else:
    out = subprocess.run([node, str(ROOT / "tests" / "rbrowser_page_harness.js"), str(STATIC / "js" / "rbrowser.js"), str(STATIC / "rbrowser.html"),
                          str(STATIC / "js" / "rbrowser-admin.js"), str(STATIC / "js" / "dashboard.js")],
                         capture_output=True, text=True, timeout=120)
    rows = [json.loads(l[7:]) for l in out.stdout.splitlines() if l.startswith("RESULT ")]
    check("the harness ran", len(rows) >= 200, out.stderr[-300:] + out.stdout[-300:])
    check("the harness did not crash", not any(r["name"] == "harness crashed" for r in rows))
    for r in rows:
        check(("" if r["name"].startswith(("admin:", "dashboard:")) else "rbrowser.js: ") + r["name"], r["ok"], r["detail"])

if failed:
    print(f"\ntest_rbrowser_page: {len(failed)} FAILED: " + "; ".join(failed))
    sys.exit(1)
print("\ntest_rbrowser_page: all checks passed")
