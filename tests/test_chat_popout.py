"""Pop-out stream chat and picture-in-picture.

Covers the room helper that keeps a second chat socket of the same user from
announcing joins and leaves, and the markup rules of watch.html and live.html
(chat-only mode, feature-detected PiP button). The live behaviour over real
sockets is in tools/smoke_checks/check_pip.py.

Run: venv/bin/python tests/test_chat_popout.py
"""

import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import server  # noqa: E402

WATCH = (ROOT / "static" / "watch.html").read_text()
LIVE = (ROOT / "static" / "live.html").read_text()


class FakeWs:
    def __init__(self, closed=False):
        self.closed = closed


def room(*entries):
    server.chat_rooms["t"] = set(entries)


def test_helper_sees_a_second_socket_of_the_same_user():
    a1, a2, b = FakeWs(), FakeWs(), FakeWs()
    room((a1, 1, "a", "user"), (a2, 1, "a", "user"), (b, 2, "b", "user"))
    assert server._user_has_other_socket("t", 1, a1)
    assert server._user_has_other_socket("t", 1, a2)
    assert not server._user_has_other_socket("t", 2, b)


def test_helper_ignores_own_socket_and_other_users():
    a1, b = FakeWs(), FakeWs()
    room((a1, 1, "a", "user"), (b, 2, "b", "user"))
    assert not server._user_has_other_socket("t", 1, a1)
    assert not server._user_has_other_socket("missing-room", 1, a1)


def test_both_sockets_closing_together_announce_one_leave():
    """Both close frames are processed before either cleanup runs: both are
    flagged closed, but each is still in the room until its own finally."""
    a1, a2 = FakeWs(closed=True), FakeWs(closed=True)
    e1, e2 = (a1, 1, "a", "user"), (a2, 1, "a", "user")
    room(e1, e2)
    announced = 0
    for ws, entry in ((a1, e1), (a2, e2)):  # the two finally blocks, one after the other
        server.chat_rooms["t"].discard(entry)
        if not server._user_has_other_socket("t", 1, ws):
            announced += 1
    assert announced == 1, f"leave announced {announced} times"


def test_helper_after_discard_matches_leave_rule():
    a1, a2 = FakeWs(), FakeWs()
    e1, e2 = (a1, 1, "a", "user"), (a2, 1, "a", "user")
    room(e1, e2)
    server.chat_rooms["t"].discard(e2)
    assert server._user_has_other_socket("t", 1, a2), "main tab still connected: no leave"
    server.chat_rooms["t"].discard(e1)
    assert not server._user_has_other_socket("t", 1, a1), "last socket gone: leave is announced"


def test_join_leave_and_voice_sites_use_the_rule():
    src = inspect.getsource(server.handle_chat_websocket)
    assert src.count("_user_has_other_socket(") == 3, "join, channel switch and disconnect"
    assert "if announce_join:" in src
    assert src.count("if not still_here:") == 2
    # closing a socket must not end a voice call joined on another socket
    assert re.search(r'vc_users\[user_id\]\.get\("ws"\) is ws', src)


def test_sockets_of_one_user_share_one_state_dict():
    server.chat_user_state.pop(77, None)
    server._chat_state_refs.pop(77, None)
    main = server._chat_state_acquire(77, {"anonymous": False, "nickname": None, "avatar": {}})
    pop = server._chat_state_acquire(77, {"anonymous": False, "nickname": None, "avatar": {}})
    assert main is pop and server.chat_user_state[77] is main
    # what the HTTP handlers do: update the registry entry
    server.chat_user_state[77]["anonymous"] = True
    assert main["anonymous"] is True and pop["anonymous"] is True, "older socket must see the change"
    server._chat_state_release(77)
    assert server.chat_user_state[77]["anonymous"] is True, "state stays while one socket is left"
    server._chat_state_release(77)
    assert 77 not in server.chat_user_state and 77 not in server._chat_state_refs


def test_a_new_socket_keeps_the_live_state_of_an_open_socket():
    """The database values were read before the handshake; a change made over
    HTTP since then is already in the live dict and must not be overwritten."""
    server.chat_user_state.pop(78, None)
    server._chat_state_refs.pop(78, None)
    main = server._chat_state_acquire(78, {"anonymous": False, "nickname": None, "avatar": {}})
    server.chat_user_state[78]["anonymous"] = True  # anonymous switched on over HTTP
    server.chat_user_state[78]["nickname"] = "live"
    pop = server._chat_state_acquire(78, {"anonymous": False, "nickname": "stale", "avatar": {"old": 1}})
    assert main is pop
    assert main["anonymous"] is True and main["nickname"] == "live" and main["avatar"] == {}
    server._chat_state_release(78)
    server._chat_state_release(78)
    assert 78 not in server.chat_user_state


def test_the_first_socket_takes_the_database_values():
    server.chat_user_state.pop(79, None)
    server._chat_state_refs.pop(79, None)
    first = server._chat_state_acquire(79, {"anonymous": True, "nickname": "n", "avatar": {"a": 1}})
    assert first == {"anonymous": True, "nickname": "n", "avatar": {"a": 1}}
    server._chat_state_release(79)


def test_acquire_runs_inside_the_try_that_releases_it():
    src = inspect.getsource(server.handle_chat_websocket)
    acquire = src.index("_chat_state_acquire(user_id")
    try_pos = src.rindex("\n    try:\n", 0, acquire)
    assert "await " not in src[try_pos:acquire], "no await between the try and the acquire"
    assert src.index("finally:", acquire) < src.index("_chat_state_release(user_id)")
    # nothing between the handshake and the try may suspend the task
    assert "await " not in src[src.rindex("await ws.prepare(request)", 0, try_pos) + 25:try_pos]


class _AsyncNull:
    """Stand-in for db: every method is an async no-op returning None."""
    def __getattr__(self, name):
        async def call(*a, **k):
            return None
        return call


def test_cancelled_right_after_the_handshake_leaks_no_reference():
    import asyncio

    uid = 9101
    server.chat_user_state.pop(uid, None)
    server._chat_state_refs.pop(uid, None)
    online_before = server._online_users.get(uid)

    class Tok:
        user_id = uid
        token_id = "t-leak"

    class FakeResp:
        closed = False
        def __init__(self, *a, **k): pass
        async def prepare(self, request): return self
        async def send_json(self, *a, **k): pass
        async def close(self, *a, **k): pass
        def __aiter__(self): return self
        async def __anext__(self): raise StopAsyncIteration

    class DB(_AsyncNull):
        async def get_user_by_id(self, user_id):
            return {"id": uid, "username": "leaky", "role": "user", "chat_anonymous": 0, "nickname": None, "avatar": None}
        async def get_enabled_outgoing_webhooks_for_event(self, event):
            return []
        async def get_dm_conversations(self, user_id, *a, **k):
            raise asyncio.CancelledError()  # the client drops right after the handshake

    class Req:
        transport = None
        headers = {}

    async def auth(request):
        return Tok()

    saved = (server.authenticate_request, server.db, server.web.WebSocketResponse)
    server.authenticate_request, server.db, server.web.WebSocketResponse = auth, DB(), FakeResp
    try:
        try:
            asyncio.run(server.handle_chat_websocket(Req()))
        except asyncio.CancelledError:
            pass
    finally:
        server.authenticate_request, server.db, server.web.WebSocketResponse = saved
    assert uid not in server._chat_state_refs, "state reference leaked"
    assert uid not in server.chat_user_state, "state dict leaked"
    assert server._online_users.get(uid) == online_before, "online count leaked"


def test_chat_handler_uses_the_shared_state():
    src = inspect.getsource(server.handle_chat_websocket)
    assert "_chat_state_acquire(user_id" in src and "_chat_state_release(user_id)" in src
    assert "chat_user_state[user_id] = my_state" not in src
    assert "chat_user_state.pop(user_id" not in src


def test_watch_page_chat_only_mode():
    assert "get('chat') === 'only'" in WATCH
    head = WATCH.split("</head>")[0]
    assert "classList.add('chat-only')" in head, "class set before first paint"
    # chat-only rules come after the mobile rules and hide the player column
    assert WATCH.index("@media (max-width: 900px)") < WATCH.index("html.chat-only .viewer-chat {")
    assert "html.chat-only .viewer-main" in WATCH
    # no player, no refresh poll, no voice in the pop-out
    assert re.search(r"if \(chatOnly\) \{[^}]*\n\s*\} else if \(streamData\.is_live === 1\) \{", WATCH)
    assert "if (!chatOnly) {\n                    refreshInterval" in WATCH
    assert "if (!chatOnly) {\n                    VoiceChat.init" in WATCH
    # same loading path as the normal page: stream API then join with the stream key
    assert "fetch(`/api/streams/${streamId}`" in WATCH
    assert "type: 'join'" in WATCH and "stream_key: streamKey" in WATCH


def test_watch_page_has_no_server_side_chat_mode():
    src = inspect.getsource(server.http_watch_stream_page)
    assert "chat" not in src and "query" not in src, "same page, same checks for ?chat=only"


def test_pop_out_button_opens_the_chat_only_url():
    assert 'id="chat-popout-btn"' in WATCH
    assert "/watch/${encodeURIComponent(streamId)}?chat=only" in WATCH
    assert "portal-chat-${streamId}" in WATCH, "named window, reused on a second click"


def test_pip_button_is_hidden_until_feature_detected():
    for name, page in (("watch", WATCH), ("live", LIVE)):
        assert re.search(r"\.pip-btn \{ display: none; \}", page), name
        assert ".pip-btn.supported { display: flex; }" in page, name
        assert 'id="pip-btn"' in page, name
        assert "document.pictureInPictureEnabled" in page, name
        assert "requestPictureInPicture" in page, name
        # Safari presentation mode
        assert "webkitSupportsPresentationMode('picture-in-picture')" in page, name
        assert "webkitSetPresentationMode" in page, name
        # the video element is looked up again at click time
        assert re.search(r"async function togglePip\(\) \{\s*const video = document.getElementById\('stream-video'\)", page), name
        assert "classList.toggle('supported'" in page, name


def test_pip_button_is_reachable_with_native_hls_and_refreshed_on_metadata():
    for name, page in (("watch", WATCH), ("live", LIVE)):
        native = page[page.index("canPlayType('application/vnd.apple.mpegurl')"):]
        native = native[:native.index("} else")]
        # the native branch must not hide the whole bar the PiP button sits in
        assert ".player-controls').style.display = 'none'" not in native, name
        assert "classList.add('native-hls')" in native, name
        assert "classList.remove('native-hls')" in page, name
        assert ".player-controls.native-hls.pip-unsupported { display: none; }" in page, name
        assert "classList.toggle('pip-unsupported'" in page, name
        assert ".player-controls.native-hls .player-control-group:not(.pip-group) { display: none; }" in page, name
        assert ".player-controls.native-hls .fullscreen-btn:not(.pip-btn) { display: none; }" in page, name
        assert 'class="player-control-group pip-group"' in page, name
        # Safari may report PiP support only once the media has loaded
        events = re.search(r"\[('enterpictureinpicture'[^\]]*)\]\s*\.forEach", page)
        assert events and "'loadedmetadata'" in events.group(1), name


def test_new_labels_are_plain_text():
    chunks = re.findall(r"(?:Picture in picture[^<\n]*|Pop out[^<\n]*)", WATCH + LIVE)
    assert chunks and all(c.isascii() for c in chunks), chunks


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except Exception as e:
                failed += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
