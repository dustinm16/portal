"""The third-party scripts and styles of the pages are vendored: no page loads code from another host.

Run: venv/bin/python tests/test_vendor_libs.py

* every file under static/vendor/<library>/ is listed in that library's README with its sha256, the file
  matches that hash, and the README names the pinned version and the sha512 of the npm tarball it came from
* every reference from a page to a vendored file carries the ?v= of the library version, and the file exists
* no HTML page, script or stylesheet of the portal (the vendored libraries themselves are covered by the
  hash check) names a script or style on another host: <script src>, <link> of a style or preload kind,
  ES module imports, CSS @import and url(), and a script or link element built in code
* the content security policy the real middleware sends names no CDN host in script-src, style-src or
  font-src, and the overlay page's policy names none either

Failing on the old code: the pages named cdn.jsdelivr.net and the policy allowed it.
"""

import asyncio
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import outbound_guard  # noqa: E402

outbound_guard.install()

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


VENDOR = ROOT / "static" / "vendor"
# library directory -> (version the pages ask for, sha512 of the npm tarball as the registry's dist.integrity,
# main file, sha256 of that file). The values are pinned here as well as in the README of each library, so
# changing a vendored file or a README row alone fails; both were copied from the READMEs (the registry
# cannot be asked offline).
LIBS = {
    "hls.js": ("1.5.17",
        "wA66nnYFvQa1o4DO/BFgLNRKnBTVXpNeldGRBJ2Y0SvFtdwvFKCbqa9zhHoZLoxHhZ+jYsj3aIBkWQQCPNOhMw==",
        "hls.min.js", "484054e8cd03d3f6d1781fb7f402bdc318d8a4c527f933a95c624e27cc9a9470"),
    "xterm": ("5.3.0",
        "8QqjlekLUFTrU6x7xck1MsPzPA571K5zNqWm0M0oroYEWVOptZ0+ubQSkQ3uxIEhcIHRujJy6emDWX4A7qyFzg==",
        "xterm.js", "f0aea0f75f48559013ae6643c2479dd737d26da42d5524e6d2b70915ae6523c7"),
    "xterm-addon-fit": ("0.8.0",
        "yj3Np7XlvxxhYF/EJ7p3KHaMt6OdwQ+HDu573Vx1lRXsVxOcnVJs51RgjZOouIZOczTsskaS+CpXspK81/DLqw==",
        "xterm-addon-fit.js", "10f3194c5f17c1786fb7d5db865c1ec8539b6736a318063fd38bdaaf7c46848f"),
    "chart.js": ("4.4.7",
        "pwkcKfdzTMAU/+jNosKhNL2bHtJc/sSmYgVbuGTEDhzkrhmyihmP7vUc/5ZK9WopidMDHNe3Wm7jOd/WhuHWuw==",
        "chart.umd.js", "2812cb8825fdc57469eb2f7bb055e9429244e599920511ee477e828499b632cb"),
    "highlight.js": ("11.12.0",
        "KvOKXODaiFmId9xaq3xc5xCL66wVLUuOngDbO9B/kewbFTqdGbn2nJxNhN3H5R1cgDTVj6R8vH0zgiNDEGjpDw==",
        "highlight.min.js", "8ab71eb09c51f501e5e25157d9cff100e46cc29bcbfc744d0b746d451fca7f53"),
    "marked": ("18.3.0",
        "ed8zmPXlBb3UfGXN5iHMQyMhFpdqLgoV5umUXx/Q1R+FW3q8VpqpyoKUwlENL9appo2UMvNLURDVaT3AMOryGA==",
        "marked.umd.js", "f8c7f128939415995e2219e8a84bec42fab27f5980d22e361339e6901da5eadf"),
    "dompurify": ("3.5.0",
        "LYC0ZkE8P1V42JsRYTwMdme/2ET8SpOc5AA2eOFjP/IadvRd2fwiT4TVz5vkfy0XUx12aS2UaRkTnfVPNOv9vw==",
        "purify.min.js", "f69a46022ab1f53e969c8ebbca98172c8995785a9b3be72ea4a12d25b1a1bf67"),
    "novnc": ("1.4.0",
        "kW6ALMc5BuH08e/ond/I1naYcfjc19JYMN1EdtmgjjjzPGCjW8fMtVM3MwM6q7YLRjPlQ3orEvoKMgSS7RkEVQ==",
        "core/rfb.js", "f497c8b080f76aee1667a3c41db61be178f93e9ce4c39d150b8bcdbefdc2b0ca"),
}
ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|.*?`([0-9a-f]{64})`\s*\|\s*$")

check("the vendored libraries are exactly the expected ones",
      sorted(p.name for p in VENDOR.iterdir() if p.is_dir()) == sorted(LIBS), str(sorted(p.name for p in VENDOR.iterdir())))
for lib, (ver, integrity, main, main_sha256) in sorted(LIBS.items()):
    d = VENDOR / lib
    readme = (d / "README.md").read_text(encoding="utf-8") if (d / "README.md").is_file() else ""
    check(f"{lib}: a README names the version {ver}", f"{ver} (vendored)" in readme and f"@{ver}" in readme)
    check(f"{lib}: the README says the tarball came from registry.npmjs.org and has the sha512",
          "https://registry.npmjs.org/" in readme and "sha512" in readme)
    check(f"{lib}: the README carries the registry's sha512 of the tarball", integrity in readme)
    check(f"{lib}: the README lists {main} with the pinned sha256", f"`{main}`" in readme and main_sha256 in readme
          and any(line.lstrip().startswith(f"| `{main}`") and main_sha256 in line for line in readme.splitlines()))
    check(f"{lib}: {main} on disk has the pinned sha256",
          (d / main).is_file() and hashlib.sha256((d / main).read_bytes()).hexdigest() == main_sha256)
    listed = {}
    for line in readme.splitlines():
        m = ROW.match(line)
        if m:
            listed[m.group(1)] = m.group(2)
    on_disk = sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file() and p.name != "README.md")
    check(f"{lib}: every file in the folder is listed in the README and no listed file is missing",
          sorted(listed) == on_disk, f"listed={sorted(listed)} disk={on_disk}")
    bad = [f for f, h in listed.items() if not (d / f).is_file() or hashlib.sha256((d / f).read_bytes()).hexdigest() != h]
    check(f"{lib}: every file matches its recorded sha256", not bad, str(bad))
    check(f"{lib}: a licence file is included", any(n.lower().startswith("licen") for n in on_disk), str(on_disk))
check("the xterm.js hash is the one of the 1.20.0 vendoring (unchanged)",
      hashlib.sha256((VENDOR / "xterm" / "xterm.js").read_bytes()).hexdigest()
      == "f0aea0f75f48559013ae6643c2479dd737d26da42d5524e6d2b70915ae6523c7")

# ---- the pages reference the vendored files with the library version -----------------------------------------
STATIC = ROOT / "static"
VREF = re.compile(r"""/static/vendor/([A-Za-z0-9.-]+)/([A-Za-z0-9_./-]+?)(\?v=([A-Za-z0-9.]+))?(?=["'`\s)])""")
refs = []
for page in sorted(STATIC.glob("*.html")) + sorted((STATIC / "js").glob("*.js")):
    for m in VREF.finditer(page.read_text(encoding="utf-8")):
        refs.append((page.name, m.group(1), m.group(2), m.group(4)))
# A library's INTERNAL module that a page imports beside the library's entry file must be asked for at exactly the URL the
# library's own relative import resolves to (no query), or the browser would load the module twice. It is allowed only for
# the pairs named here, and only when the same page loads the library's entry file with the library version.
INTERNAL = {("rbrowser.js", "novnc", "core/input/keysymdef.js"): "core/rfb.js"}
for page, lib, path, ver in refs:
    if lib == "codemirror":
        continue
    if (page, lib, path) in INTERNAL:
        check(f"{page} -> vendor/{lib}/{path}: an internal module without a query, beside the versioned entry file",
              ver is None and (VENDOR / lib / path).is_file() and (page, lib, INTERNAL[(page, lib, path)], LIBS[lib][0]) in refs,
              f"{lib} {path} v={ver}")
        continue
    check(f"{page} -> vendor/{lib}/{path}: the file exists and its ?v= is the library version",
          lib in LIBS and (VENDOR / lib / path).is_file() and ver == LIBS[lib][0],
          f"{lib} {path} v={ver}")
want_pages = {
    "live.html": "hls.js", "watch.html": "hls.js", "streams.html": "hls.js", "vod-player.html": "hls.js",
    "terminal.html": "xterm", "admin.html": "chart.js", "chat.html": "highlight.js", "github.html": "marked",
}
for page, lib in want_pages.items():
    check(f"{page} loads {lib} from the vendored folder", any(r[0] == page and r[1] == lib for r in refs))
check("github.html loads DOMPurify from the vendored folder", any(r[0] == "github.html" and r[1] == "dompurify" for r in refs))
check("terminal.html loads the fit addon from the vendored folder", any(r[0] == "terminal.html" and r[1] == "xterm-addon-fit" for r in refs))
check("vnc.html imports noVNC from the vendored folder", any(r[0] == "vnc.html" and r[1] == "novnc" and r[2] == "core/rfb.js" for r in refs))

# ---- no page or script loads a script or style from another host -----------------------------------------------
ABS = r"""(?:https?:)?//"""
SCRIPT_TAG = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']?(" + ABS + r"[^\"' >]+)", re.I)
LINK_TAG = re.compile(r"<link\b([^>]*)>", re.I)
HREF = re.compile(r"""\bhref\s*=\s*["']?([^"' >]+)""", re.I)
REL = re.compile(r"""\brel\s*=\s*["']?([^"'>]+)""", re.I)
ES_IMPORT = re.compile(r"""\bimport\s*(?:[\w*{},\s]+?\sfrom\s*)?\(?\s*["'](""" + ABS + r"""[^"']+)""")
CSS_IMPORT = re.compile(r"""@import\s+(?:url\(\s*)?["']?(""" + ABS + r"""[^"')\s]+)""", re.I)
CSS_URL = re.compile(r"""url\(\s*["']?(""" + ABS + r"""[^"')\s]+)""", re.I)
BUILT = re.compile(r"""createElement\(\s*["'](?:script|link)["']\s*\)""")
BUILT_URL = re.compile(r"""\.(?:src|href)\s*=\s*["'`](""" + ABS + r"""[^"'`]+)|setAttribute\(\s*["'](?:src|href)["']\s*,\s*["'`](""" + ABS + r"""[^"'`]+)""")
STYLE_RELS = ("stylesheet", "preload", "modulepreload", "prefetch", "preconnect", "dns-prefetch", "icon", "manifest")
HOSTS = ("jsdelivr", "unpkg.com", "cdnjs", "fonts.googleapis.com", "ajax.googleapis.com", "gstatic.com", "bootstrapcdn", "cloudflare.com/ajax", "esm.sh", "skypack")


def own_host(url):
    return url.startswith("https://{{HOSTNAME}}")


found = []
files = sorted(STATIC.glob("*.html")) + sorted((STATIC / "js").glob("*.js")) + sorted((STATIC / "css").glob("*.css")) + [STATIC / "sw.js"]
for f in files:
    t = f.read_text(encoding="utf-8")
    for m in SCRIPT_TAG.finditer(t):
        found.append((f.name, "script src", m.group(1)))
    for m in LINK_TAG.finditer(t):
        rel, href = REL.search(m.group(1)), HREF.search(m.group(1))
        if rel and href and any(r in rel.group(1).lower().split() for r in STYLE_RELS) \
                and re.match(ABS, href.group(1)) and not own_host(href.group(1)):
            found.append((f.name, "link " + rel.group(1), href.group(1)))
    for rx, what in ((ES_IMPORT, "import"), (CSS_IMPORT, "@import"), (CSS_URL, "url()")):
        for m in rx.finditer(t):
            found.append((f.name, what, m.group(1)))
    if f.suffix == ".js" or f.suffix == ".html":
        for m in BUILT.finditer(t):
            near = t[m.start(): m.start() + 600]
            for u in BUILT_URL.finditer(near):
                found.append((f.name, "built element", u.group(1) or u.group(2)))
    for h in HOSTS:
        if h in t.lower():
            found.append((f.name, "names a library host", h))
check("no HTML page, script or stylesheet loads a script or style from another host", not found, "; ".join(map(str, found)))
check("the scan saw the pages", len(files) > 60, str(len(files)))

# a deliberately bad page proves the scan can see each kind of reference
SAMPLES = [
    '<script src="https://cdn.example/x.js"></script>', '<script src="//cdn.example/x.js"></script>',
    '<link rel="stylesheet" href="https://cdn.example/x.css">', '<link href="https://cdn.example/x.css" rel="stylesheet">',
    "<script type=\"module\">import R from 'https://cdn.example/rfb.js';</script>",
    "import('https://cdn.example/x.js')", "@import url('https://cdn.example/x.css');", "a{background:url(https://cdn.example/f.woff)}",
    "var s = document.createElement('script'); s.src = 'https://cdn.example/x.js';",
]
saw = []
for s in SAMPLES:
    hit = bool(SCRIPT_TAG.search(s) or [m for m in LINK_TAG.finditer(s) if HREF.search(m.group(1)) and re.match(ABS, HREF.search(m.group(1)).group(1))]
               or ES_IMPORT.search(s) or CSS_IMPORT.search(s) or CSS_URL.search(s)
               or (BUILT.search(s) and BUILT_URL.search(s)))
    saw.append(hit)
check("the scan recognises each way a page can load code from another host", all(saw), str(saw))
check("the portal's own links are not flagged", not SCRIPT_TAG.search('<script src="/static/js/portal.js?v=52"></script>')
      and not ES_IMPORT.search("import RFB from '/static/vendor/novnc/core/rfb.js?v=1.4.0';"))


# ---- the content security policy ---------------------------------------------------------------------------------
async def csp_of_middleware():
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    import aiohttp
    import server
    from database import Database
    tmp = tempfile.TemporaryDirectory()
    saved = server.db
    server.db = Database(str(Path(tmp.name) / "t.db"))
    await server.db.connect()
    app = web.Application(middlewares=[server.security_headers_middleware])

    async def page(request):
        return web.Response(text="<html></html>", content_type="text/html")
    app.router.add_get("/page", page)
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"http://127.0.0.1:{srv.port}/page") as r:
                return r.headers.get("Content-Security-Policy", "")
    finally:
        await srv.close()
        await server.db.close()
        server.db = saved
        tmp.cleanup()


try:
    csp = asyncio.run(asyncio.wait_for(csp_of_middleware(), 60))
except Exception as exc:  # a hang or an error prints FAIL, not a stuck run
    csp = ""
    check("the middleware answered", False, repr(exc))
directives = {d.strip().split(" ", 1)[0]: d.strip().split(" ")[1:] for d in csp.split(";") if d.strip()}
hosts = lambda name: [x for x in directives.get(name, []) if "." in x or "://" in x]
check("script-src allows self, inline script and blob only (no host)", directives.get("script-src") == ["'self'", "'unsafe-inline'", "blob:"], str(directives.get("script-src")))
check("style-src allows self and inline style only (no host)", directives.get("style-src") == ["'self'", "'unsafe-inline'"], str(directives.get("style-src")))
check("font-src allows self only", directives.get("font-src") == ["'self'"], str(directives.get("font-src")))
check("no directive names jsDelivr", "jsdelivr" not in csp and "cdn" not in csp.lower(), csp)
check("what is still allowed on purpose is unchanged: https images, wss connect, the two YouTube frame hosts",
      directives.get("img-src") == ["'self'", "data:", "https:"] and directives.get("connect-src") == ["'self'", "wss:"]
      and directives.get("frame-src") == ["'self'", "https://www.youtube.com", "https://www.youtube-nocookie.com"]
      and directives.get("default-src") == ["'self'"] and directives.get("worker-src") == ["'self'", "blob:"]
      and directives.get("frame-ancestors") == ["'self'"], csp)
check("the policy still has its other directives (base-uri, form-action, media-src)",
      all(k in directives for k in ("base-uri", "form-action", "media-src")), csp)
server_src = (ROOT / "server.py").read_text(encoding="utf-8")
check("server.py names no CDN host at all", "jsdelivr" not in server_src.lower())

# --- source maps (E20): the READMEs say what the scripts really do ---------------------------------------------------
_hl = VENDOR / "highlight.js"
_hl_js = (_hl / "highlight.min.js").read_text(encoding="utf-8")
_hl_readme = (_hl / "README.md").read_text(encoding="utf-8")
check("E20: highlight.min.js names no source map, and its README does not say its last line names one",
      "sourceMappingURL" not in _hl_js and "the last line of the script names it" not in _hl_readme
      and "ends without a `sourceMappingURL` comment" in _hl_readme)
_mapped = sorted(str(p.relative_to(VENDOR)) for p in VENDOR.rglob("*.js") if p.is_file()
                 if re.search(r"sourceMappingURL=\S+\.map\s*$", p.read_text(encoding="utf-8", errors="replace")[-400:]))
_vendor_readme = (VENDOR / "README.md").read_text(encoding="utf-8") if (VENDOR / "README.md").is_file() else ""
check("E20: the vendor README names every script that ends with a sourceMappingURL comment and says the .map files are not shipped",
      len(_mapped) == 6 and all(f"`{m}`" in _vendor_readme for m in _mapped) and "not shipped" in _vendor_readme
      and not any(VENDOR.rglob("*.map")), str(_mapped))

if failures:
    print(f"\ntest_vendor_libs: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_vendor_libs: all checks passed")
