"""An uploads folder that is a link to another disk is still served to signed-in members (1.24.1).

The signed-in upload route judges the file it resolves to. A subfolder of static/uploads (chat, thumbnails) that is
a symbolic link to another place (for example another disk) resolves outside the resolved uploads folder; 1.24.0
served those files and the first 1.24.1 build answered 404. A file is now accepted inside the resolved location of
its own folder too, while a link that leads somewhere else (outside both, or out of the folder to another folder's
file that is not named by the folder it sits in) is still 404, and the thumbnail check still reads the file by its
folder. Run: venv/bin/python tests/test_upload_linked_folder.py   (30 second deadline per part)

The second part (1.24.2) pins what keeps the same linked folder from being served to anyone by the plain static
route: add_static is registered without follow_symlinks=True, and every spelling of the path that skips the
signed-in upload route stays 401 or 404 for an anonymous request.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grant_harness import boot, check, finish, server, shutdown  # noqa: E402
from aiohttp import ClientSession, web  # noqa: E402
from aiohttp.test_utils import make_mocked_request  # noqa: E402
from yarl import URL  # noqa: E402


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


SPELLINGS = (
    "/static/uploads/chat/a.png",
    "/static/uploads%2Fchat/a.png",
    "/static/uploads%2Fchat%2Fa.png",
    "/static/uploads%2fchat%2fa.png",
    "/static//uploads/chat/a.png",
    "/static///uploads//chat//a.png",
    "/static/./uploads/chat/a.png",
    "/static/%2e/uploads/chat/a.png",
    "/static/x/../uploads/chat/a.png",
    "/static/x%2f..%2fuploads/chat/a.png",
    "/static/uploads/./chat/a.png",
    "/static/uploads/chat/../chat/a.png",
    "/static/uploads/%63hat/a.png",
    "/static/%75ploads/chat/a.png",
    "/static/uploads/chat/%61.png",
    "/static/linked/a.png",                      # a linked folder outside uploads, reached by the plain static route
    "/static/linked_file.png",                   # a linked file outside uploads
)


async def static_route_part():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        static, outside = tmp / "static", tmp / "disk"
        (static / "uploads").mkdir(parents=True)
        (outside / "chat").mkdir(parents=True)
        (outside / "chat" / "a.png").write_bytes(b"\x89PNG")
        os.symlink(outside / "chat", static / "uploads" / "chat")
        os.symlink(outside / "chat", static / "linked")
        os.symlink(outside / "chat" / "a.png", static / "linked_file.png")
        (static / "plain.txt").write_text("public")
        real_dir = server.STATIC_DIR
        server.STATIC_DIR = static
        env = None
        try:
            env = await boot(names=("a",), superadmin=())
            statics = [r for r in env.srv.app.router.resources() if isinstance(r, web.StaticResource)]
            check("exactly one plain static route is registered", len(statics) == 1, str(len(statics)))
            follow = getattr(statics[0], "_follow_symlinks", "missing") if statics else "missing"
            check("the plain static route is registered without follow_symlinks=True", follow is False, repr(follow))
            async with ClientSession() as anon:
                async def status(path):
                    async with anon.get(URL(env.base + path, encoded=True), allow_redirects=False) as r:
                        return r.status
                ok = await status("/static/plain.txt")
                check("the plain static route still serves an ordinary file", ok == 200, str(ok))
                for path in SPELLINGS:
                    st = await status(path)
                    check("anonymous " + path + " is 401 or 404", st in (401, 404), str(st))
            async with env.sessions["a"].get(env.base + "/static/linked/a.png", allow_redirects=False) as r:
                check("a signed-in member does not get a linked folder outside uploads from the plain static route",
                      r.status in (401, 404), str(r.status))
        finally:
            if env is not None:
                await shutdown(env)
            server.STATIC_DIR = real_dir


asyncio.run(asyncio.wait_for(main(), 30))
asyncio.run(asyncio.wait_for(static_route_part(), 30))
finish("test_upload_linked_folder")
