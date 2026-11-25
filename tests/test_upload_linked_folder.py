"""An uploads folder that is a link to another disk is still served to signed-in members (1.24.1).

The signed-in upload route judges the file it resolves to. A subfolder of static/uploads (chat, thumbnails) that is
a symbolic link to another place (for example another disk) resolves outside the resolved uploads folder; 1.24.0
served those files and the first 1.24.1 build answered 404. A file is now accepted inside the resolved location of
its own folder too, while a link that leads somewhere else (outside both, or out of the folder to another folder's
file that is not named by the folder it sits in) is still 404, and the thumbnail check still reads the file by its
folder. Run: venv/bin/python tests/test_upload_linked_folder.py   (30 second deadline)
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grant_harness import check, finish, server  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402


class Tok:
    user_id = 1
    token_id = "t"


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        static, outside, secret = tmp / "static", tmp / "disk", tmp / "elsewhere"
        for d in (static / "uploads" / "thumbnails", outside / "chat", secret):
            d.mkdir(parents=True)
        (outside / "chat" / "a.png").write_bytes(b"\x89PNG")
        (secret / "s.png").write_bytes(b"\x89PNG-secret")
        (static / "uploads" / "own.png").write_bytes(b"\x89PNG")
        (static / "uploads" / "thumbnails" / "t.png").write_bytes(b"\x89PNG")        # named by no stream
        os.symlink(outside / "chat", static / "uploads" / "chat")                      # the folder is a link to another disk
        os.symlink(secret / "s.png", outside / "chat" / "leak.png")                    # a file in it that leads elsewhere
        os.symlink(static / "uploads" / "thumbnails" / "t.png", outside / "chat" / "thumb.png")  # to another upload folder's file

        async def authed(request):
            return Tok()
        class NoStreams:
            async def get_stream_by_thumbnail_url(self, url):
                return None
        real_auth, real_dir, real_db = server.authenticate_request, server.STATIC_DIR, server.db
        server.authenticate_request, server.STATIC_DIR, server.db = authed, static, NoStreams()

        async def get(path):
            req = make_mocked_request("GET", "/static/uploads/" + path, match_info={"path": path})
            try:
                resp = await server.http_authenticated_upload(req)
            except Exception as exc:                      # an HTTP exception answers too
                resp = exc
            return resp.status, resp.headers.get("Cache-Control")

        try:
            st, cc = await get("chat/a.png")
            check("a file in an uploads folder that is a link to another disk is served (200, Cache-Control: private)",
                  st == 200 and cc == "private", f"{st} {cc}")
            st, _ = await get("own.png")
            check("a file directly in the uploads folder is served as before", st == 200, str(st))
            st, _ = await get("chat/leak.png")
            check("a link inside the linked folder that leaves it for another place is 404", st == 404, str(st))
            st, _ = await get("chat/thumb.png")
            check("a link from the folder to an upload no stream names is still judged as that upload (404)", st == 404, str(st))
            st, _ = await get("chat/missing.png")
            check("a missing file in the linked folder is 404", st == 404, str(st))
            st, _ = await get("../disk/chat/a.png")
            check("a path that climbs out is 400", st == 400, str(st))
        finally:
            server.authenticate_request, server.STATIC_DIR, server.db = real_auth, real_dir, real_db


asyncio.run(asyncio.wait_for(main(), 30))
finish("test_upload_linked_folder")
