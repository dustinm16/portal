"""The grant harness keeps what a test uploads out of the checkout (1.24.2).

Tests built on tests/grant_harness.py write chat uploads, thumbnails and emotes. They must land in a temporary folder
that is removed at exit, never in the checkout's static/uploads, and the static files the pages need must still be
served. Run: venv/bin/python tests/test_harness_uploads_isolated.py
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

import aiohttp  # noqa: E402
import server  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CHECKOUT_UPLOADS = ROOT / "static" / "uploads"


def listing():
    return sorted(str(p) for p in CHECKOUT_UPLOADS.rglob("*")) if CHECKOUT_UPLOADS.exists() else None


async def main():
    before = listing()
    existed = CHECKOUT_UPLOADS.exists()
    env = await h.boot(names=("bob",), superadmin=())
    stray = []
    try:
        form = aiohttp.FormData()
        form.add_field("file", b"\x89PNG", filename="x.png", content_type="image/png")
        async with env.sessions["bob"].post(env.base + "/api/chat/upload", data=form) as r:
            body = await r.json()
            check("a chat upload is accepted", r.status == 200, f"{r.status} {body}")
        url = body.get("url", "")
        stray.append(ROOT / url.lstrip("/"))
        check("the static folder of the app is not the checkout's", Path(server.STATIC_DIR).resolve() != (ROOT / "static").resolve(),
              str(server.STATIC_DIR))
        check("the chat upload is stored under the app's static folder",
              (Path(server.STATIC_DIR) / url.removeprefix("/static/")).is_file(), url)
        check("the database's chat upload folder is under the app's static folder",
              Path(env.db.chat_upload_dir).resolve().is_relative_to(Path(server.STATIC_DIR).resolve()), env.db.chat_upload_dir)
        async with env.sessions["bob"].get(env.base + url) as r:
            check("the stored upload is served to the member", r.status == 200, str(r.status))
        async with env.sessions["bob"].get(env.base + "/static/css/portal.css") as r:
            check("an ordinary static file is still served", r.status == 200, str(r.status))
        check("the checkout's static/uploads is unchanged", listing() == before and CHECKOUT_UPLOADS.exists() == existed,
              f"{before} -> {listing()}")
    finally:
        for p in stray:
            if str(p).startswith(str(CHECKOUT_UPLOADS)):
                p.unlink(missing_ok=True)
    await h.shutdown(env)
    h.finish("test_harness_uploads_isolated")


async def guarded():
    try:
        await asyncio.wait_for(main(), 60)
    except BaseException as e:
        print(f"FAIL: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        os._exit(1)


asyncio.run(guarded())
