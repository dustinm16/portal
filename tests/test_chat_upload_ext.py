"""Chat upload names (1.24.1): a file sent as application/octet-stream keeps its extension only when the extension is
on the allowed list; any other name is stored as .bin, so an extension that browsers render (.html, .svg, .xml) is never
kept. The stored file is also fetched through the plain path to show it is a download, not a page.

Real app on a loopback test server (tests/grant_harness.py). Run: venv/bin/python tests/test_chat_upload_ext.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

import aiohttp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


async def main():
    env = await h.boot(names=("bob",), superadmin=())
    made = []
    try:
        async def post(name, ctype, data=b"<script>1</script>"):
            form = aiohttp.FormData()
            form.add_field("file", data, filename=name, content_type=ctype)
            async with env.sessions["bob"].post(env.base + "/api/chat/upload", data=form) as r:
                body = await r.json()
                if r.status == 200:
                    made.append(h.STATIC_DIR / body["url"].removeprefix("/static/"))
                return r.status, body

        for name in ("a.html", "a.svg", "a.xml", "a.xhtml", "a.htm", "a.js", "a.docx", "a.HTML"):
            st, body = await post(name, "application/octet-stream")
            check(f"octet-stream {name}: accepted and stored as .bin", st == 200 and body["url"].endswith(".bin"), f"{st} {body}")
        for name, ext in (("a.txt", ".txt"), ("a.py", ".py"), ("a.JSON", ".json"), ("a.yaml", ".yaml"), ("a.sh", ".sh")):
            st, body = await post(name, "application/octet-stream")
            check(f"octet-stream {name}: an allowed extension is kept", st == 200 and body["url"].endswith(ext), f"{st} {body}")
        st, body = await post("a.html", "text/html")
        check("text/html with .html is still refused", st == 400, f"{st} {body}")
        st, body = await post("x.png", "image/png", b"\x89PNG")
        check("a png keeps .png", st == 200 and body["url"].endswith(".png"), f"{st} {body}")
        st, body = await post("a.html", "application/octet-stream")
        async with env.sessions["bob"].get(env.base + body["url"]) as r:
            check("the stored upload is served as a download", r.status == 200 and "attachment" in r.headers.get("Content-Disposition", "")
                  and "html" not in r.headers.get("Content-Type", ""), f"{r.status} {dict(r.headers)}")
    finally:
        for p in made:
            p.unlink(missing_ok=True)
    await h.shutdown(env)
    h.finish("test_chat_upload_ext")


async def guarded():
    try:
        await asyncio.wait_for(main(), 60)
    except BaseException as e:
        print(f"FAIL: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        import os
        os._exit(1)


asyncio.run(guarded())
