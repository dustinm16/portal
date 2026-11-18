"""The key bar smoke check must not send input straight after the Ctrl+C that drops a half-typed line.

Ctrl+C flushes the tty input queue and the shell redraws its prompt a moment
later; a command sent in that gap is lost or glued to the old line, which made
the up-arrow check flaky. drop_line() waits for the prompt before returning.
A fake shell here loses all input for 0.3 s after Ctrl+C, like a loaded
machine, and runs commands that reach it afterwards (a line that was never
cleared would not print at the start of a line).

Run: venv/bin/python tests/test_keybar_smoke_sync.py
"""

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check_keybar", ROOT / "tools" / "smoke_checks" / "check_keybar.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

REDRAW_DELAY = 0.3


class FakeWS:
    """A terminal websocket in front of a fake bash that is deaf while it redraws after Ctrl+C."""

    def __init__(self):
        self.q = asyncio.Queue()
        self.line = ""
        self.deaf_until = 0.0
        self.executed = []

    def _out(self, text):
        self.q.put_nowait(text)

    async def send_json(self, msg):
        loop = asyncio.get_running_loop()
        data = msg["data"]
        if data == "\x03":
            self.line = ""
            self.deaf_until = loop.time() + REDRAW_DELAY
            self._out("^C\r\n")
            loop.call_later(REDRAW_DELAY, self._out, "$ ")
            return
        if loop.time() < self.deaf_until:
            return                      # flushed with the tty input queue
        for ch in data:
            if ch == "\r":
                cmd, self.line = self.line, ""
                self.executed.append(cmd)
                if cmd == "echo SYNC$((1+1))":
                    self._out("\r\n\x1b[?2004l\rSYNC2\r\n\x1b[?2004h$ ")   # bash with bracketed paste on
                else:
                    self._out("\r\nbash: error\r\n$ ")
            else:
                self.line += ch
                self._out(ch)

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        while True:
            data = await self.q.get()
            yield SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=data)

    async def close(self):
        pass


async def main():
    # a half-typed line, then the drop: the next command must run on a clean line
    ws = FakeWS()
    shell = check.Session(ws)
    await shell.send("ls kbcomplete_")
    assert await check.drop_line(shell, "\x03") is True
    assert ws.line == "" and ws.executed[-1] == "echo SYNC$((1+1))", ws.executed
    await shell.send("echo HI$((7000+731))\r")
    await asyncio.sleep(0.1)
    assert ws.executed[-1] == "echo HI$((7000+731))", ws.executed   # not "s kbcomplete_... echo HI"
    await shell.close()

    # what the check did before: Ctrl+C then the next command at once. It is lost in the gap.
    ws = FakeWS()
    shell = check.Session(ws)
    await shell.send("ls kbcomplete_")
    await shell.send("\x03")
    await shell.send("echo HI$((7000+731))\r")
    await asyncio.sleep(0.1)
    assert "echo HI$((7000+731))" not in ws.executed, "the fake shell must lose input sent right after Ctrl+C"
    await shell.close()

    # a shell that never comes back is reported, not hidden
    class DeadWS(FakeWS):
        async def send_json(self, msg):
            if msg["data"] == "\x03":
                self._out("^C\r\n")
                self.deaf_until = float("inf")
                return
            await super().send_json(msg)

    ws = DeadWS()
    shell = check.Session(ws)
    await shell.send("ls kbcomplete_")
    assert await check.drop_line(shell, "\x03", timeout=0.5) is False
    await shell.close()


asyncio.run(main())
print("keybar smoke sync tests passed")
