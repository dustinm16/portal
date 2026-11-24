"""Chat overlay for an OBS browser source (1.24.0): the pure parts.

A stream's owner makes one overlay token for the stream. The token reaches one thing: a read-only view of that
stream's chat as its public viewers see it, over the dedicated socket /ws/overlay. This module holds the token
helpers, the reducer that turns a chat frame into the few fields a renderer needs, and the subscriber object whose
bounded queue and writer keep a slow OBS client from ever delaying the broadcast to real chat members. The registry,
the routes and the socket handler are in server.py.
"""

import asyncio
import hashlib
import json
import re
import secrets
from typing import Optional

TOKEN_PREFIX = "ov_"
TOKEN_RE = re.compile(r"^ov_[A-Za-z0-9_-]{43}$")

# One active token per stream (the table's primary key is the stream): creating again replaces it.
MAX_SOCKETS_PER_TOKEN = 3
HISTORY_LIMIT = 50
AUTH_TIMEOUT = 5.0                  # seconds to send the first frame
SEND_TIMEOUT = 5.0                  # one send to an OBS client may take this long, then the socket is dropped
QUEUE_MAX = 100                     # frames waiting for a client; a full queue drops the socket
MAX_INBOUND_BYTES = 1024            # the first frame is a few hundred bytes; the socket's frame limit is this
CLOSE_REFUSED = 4401                # the one code for a bad, unknown, revoked or regenerated token
CLOSE_POLICY = 1008                 # a client that sends anything after its first frame
CLOSE_SLOW = 1013                   # too slow, or too many sockets on the token: try again later
TEXT_MAX = 1000
NAME_MAX = 64
IDS_MAX = 1000

# The kinds of chat row an overlay shows: what a viewer reads as a line of chat. A message an incoming webhook
# posted is one (live it has no message_type, in the history it is "webhook"); a go-live card is not.
SHOWN_TYPES = ("message", "webhook")

# The only chat frame types an overlay is ever given (the key is the type in the chat, the value the overlay's own)
ALLOWED_TYPES = {
    "message": "message",
    "message_edited": "edit",
    "message_deleted": "delete",
    "messages_pruned": "prune",
    "channel_cleared": "clear",
}


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 of a token of 256 random bits: nothing to brute-force, and the stored value reveals nothing a leaked
    database could use."""
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()


def wellformed(token) -> bool:
    return isinstance(token, str) and TOKEN_RE.match(token) is not None


def _int_id(value) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def reduce_message(m: dict) -> Optional[dict]:
    """One chat message (a live frame or a history row, as a public viewer is shown it) as the overlay's message:
    id, name, optional badge, text, time. Nothing else crosses: no account id, role, avatar, reply, picture,
    attachment, card, poll or reaction. An anonymous post is "Anonymous" with no badge. A message that has no text
    of its own (a picture or a go-live card) is not shown. A webhook post is shown under the name the chat gives it."""
    if not isinstance(m, dict):
        return None
    mid = _int_id(m.get("id"))
    if mid is None or (m.get("message_type") or "message") not in SHOWN_TYPES:
        return None
    text = m.get("message")
    if not isinstance(text, str) or not text.strip():
        return None
    anonymous = bool(m.get("anonymous"))
    name = "Anonymous" if anonymous else str(m.get("username") or "")[:NAME_MAX]
    out = {"id": mid, "name": name, "text": text[:TEXT_MAX], "time": str(m.get("created_at") or "")[:40]}
    posted_by_hook = m.get("message_type") == "webhook" or bool(m.get("webhook"))
    if not anonymous and not posted_by_hook and m.get("stream_role") in ("owner", "mod"):   # a hook is the account's tool, not the person
        out["badge"] = m["stream_role"]
    return out


def reduce_frame(frame: dict) -> Optional[dict]:
    """A frame of the chat room as the overlay's frame, or None for everything that is not on the allow-list."""
    if not isinstance(frame, dict):
        return None
    kind = ALLOWED_TYPES.get(frame.get("type"))
    if kind is None:
        return None
    if kind == "message":
        m = reduce_message(frame)
        return None if m is None else {"type": "message", **m}
    if kind == "edit":
        mid, text = _int_id(frame.get("message_id")), frame.get("message")
        if mid is None or not isinstance(text, str):
            return None
        return {"type": "edit", "id": mid, "text": text[:TEXT_MAX]}
    if kind == "delete":
        mid = _int_id(frame.get("message_id"))
        return None if mid is None else {"type": "delete", "id": mid}
    if kind == "prune":
        ids = [i for i in (frame.get("ids") or []) if _int_id(i) is not None][:IDS_MAX]
        return {"type": "prune", "ids": ids} if ids else None
    return {"type": "clear"}


def reduce_history(messages) -> dict:
    return {"type": "history", "messages": [m for m in (reduce_message(x) for x in messages or []) if m]}


def encode(frame: dict) -> str:
    return json.dumps(frame, separators=(",", ":"), ensure_ascii=False)


class Subscriber:
    """One overlay socket. offer() never waits: the frame goes into a bounded queue, and a writer task sends it with
    a timeout. A full queue or a send that does not finish drops the socket, so the chat broadcast that called
    offer() cannot be delayed by it."""

    def __init__(self, ws, transport, channel: str, stream_id: int, owner_id: int, digest: str):
        self.ws = ws
        self.transport = transport
        self.channel = channel
        self.stream_id = stream_id
        self.owner_id = owner_id
        self.digest = digest
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
        self.dead = False
        self.writer: Optional[asyncio.Task] = None
        self.close_task: Optional[asyncio.Task] = None     # the one close; the handler waits for it before it returns
        self.on_dead = None            # called once, synchronously, when the socket is dropped

    def offer(self, data: str) -> bool:
        """Queue one encoded frame. False when the socket is gone or its queue is full (the caller drops it)."""
        if self.dead:
            return False
        try:
            self.queue.put_nowait(data)
            return True
        except asyncio.QueueFull:
            return False

    async def run(self, first: str) -> None:
        """The writer: the first frame (the history), then the queue, each send bounded by SEND_TIMEOUT."""
        try:
            await asyncio.wait_for(self.ws.send_str(first), SEND_TIMEOUT)
            while not self.dead:
                data = await self.queue.get()
                if data is None:
                    break
                await asyncio.wait_for(self.ws.send_str(data), SEND_TIMEOUT)
        except asyncio.CancelledError:
            raise
        except Exception:
            # a send that timed out or failed: the client is too slow or gone
            self.kill(CLOSE_SLOW)

    def kill(self, code: int) -> None:
        """Drop the socket now (synchronously marks it, then closes in the background). Safe to call twice."""
        if self.dead:
            return
        self.dead = True
        if self.on_dead is not None:
            try:
                self.on_dead(self)
            except Exception:
                pass
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            pass
        try:
            self.close_task = asyncio.get_running_loop().create_task(self._close(code))
        except RuntimeError:
            self._abort()

    async def _close(self, code: int) -> None:
        try:
            await asyncio.wait_for(self.ws.close(code=code), 2.0)
        except Exception:
            self._abort()

    def _abort(self) -> None:
        try:
            if self.transport is not None:
                self.transport.abort()
        except Exception:
            pass
