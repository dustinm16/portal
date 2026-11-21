"""Smoke check: the web terminal key bar.

Proves what can be proven without a browser or a phone:
  - every terminal page (local shell, a terminal service, a user SSH
    connection) is served with the key bar, the helper script and the
    bumped terminal.js, with the host-key script still loaded;
  - the key sequences the served helper script produces (run under Node
    when it is installed) do what the plan promises in a real bash session
    behind /ws/terminal/<id>: Ctrl+C interrupts a running command, Tab
    completes a file name, the up arrow recalls history in normal and in
    application cursor mode.
Left to a manual check on a phone: on-screen keyboard placement, the iOS
clipboard bubble, Firefox without readText, touch focus, arrows in vim.
"""
import asyncio
import json
import re
import shutil
import tempfile
import time
from pathlib import Path

import aiohttp

ADMIN = "keybar_admin"
ADMIN_PW = "keybar-admin-pass-1234"
USER = "keybar_user"
USER_PW = "Keybar-User-Pw-1!"
GOOD_HOST = "93.184.216.34"
COMPLETE_NAME = "kbcomplete_zq81x.txt"

SETUP = '''
import asyncio, json, os
from pathlib import Path
from database import db
from auth import create_user

async def main():
    await db.connect()
    u = await create_user(%(admin)r, %(admin_pw)r, is_admin=True)
    await db.set_user_role(u["id"], "superadmin")
    await create_user(%(user)r, %(user_pw)r, is_admin=False)
    work = Path("keybar_work")
    work.mkdir(exist_ok=True)
    (work / %(name)r).write_text("x")
    sid = await db.create_service(name="keybar shell", path="/keybar-shell", plugin="terminal",
                                  config={"shell": "/bin/bash", "working_dir": str(work.resolve())})
    await db.close()
    print("RESULT " + json.dumps({"service": sid}))

asyncio.run(main())
''' % {"admin": ADMIN, "admin_pw": ADMIN_PW, "user": USER, "user_pw": USER_PW, "name": COMPLETE_NAME}

# The served helper script is the one under test: print the byte sequences it makes.
KEYS_JS = r'''
const K = require(process.argv[2]);
console.log('KEYS=' + JSON.stringify({
  ctrl_c: K.applyModifiers('c', {ctrl: true}),
  tab: '\t',
  up_normal: K.arrowSequence('up', false),
  up_app: K.arrowSequence('up', true),
  alt_x: K.applyModifiers('x', {alt: true}),
  multi: K.pasteNeedsConfirm('a\nb'),
  single: K.pasteNeedsConfirm('ls'),
  paste_clean: K.sanitizePaste('ls\x1b[201~; id\x03\x04\tok\r\n'),
  report_focus: K.isTerminalReport('\x1b[I') && K.isTerminalReport('\x1b[24;80R'),
  report_key: K.isTerminalReport('\x1b[A') || K.isTerminalReport('\x1b') || K.isTerminalReport('c'),
}));
'''


def _result(out):
    for line in reversed(out.strip().splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


class Session:
    """A /ws/terminal/<id> session that collects everything the shell prints."""

    def __init__(self, ws):
        self.ws = ws
        self.text = ""
        self._task = asyncio.ensure_future(self._pump())

    async def _pump(self):
        async for m in self.ws:
            if m.type == aiohttp.WSMsgType.TEXT:
                self.text += m.data

    async def send(self, data):
        await self.ws.send_json({"type": "input", "data": data})

    async def until(self, pattern, since=0, timeout=8.0):
        """Wait for a regex to match in the output after offset since; returns the match or None."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            m = re.search(pattern, self.text[since:])
            if m:
                return m
            await asyncio.sleep(0.05)
        return None

    def mark(self):
        return len(self.text)

    async def close(self):
        await self.ws.close()
        self._task.cancel()


async def drop_line(shell, ctrl_c, timeout=4):
    """Throw away a half-typed line with Ctrl+C and wait until the shell is back at a clean prompt.

    Ctrl+C flushes the tty input queue and readline then redraws, so input sent
    straight after it can be lost or glued to the old line. Wait for the echoed
    ^C, then prove the line is clear: a command whose output starts a line (after any
    escape sequences and carriage returns) only when it ran on its own. Returns True when that proof was seen.
    """
    at = shell.mark()
    await shell.send(ctrl_c)
    await shell.until(r"\^C", since=at, timeout=timeout)
    await asyncio.sleep(0.3)
    for _ in range(3):
        at = shell.mark()
        await shell.send("echo SYNC$((1+1))\r")
        if await shell.until(r"(?m)^(?:\x1b\[[0-9;?]*[A-Za-z]|\r)*SYNC2", since=at, timeout=timeout):
            return True
    return False


async def _open(ctx, sess, service_id):
    url = ctx.base_url.replace("https", "wss") + f"/ws/terminal/{service_id}"
    ws = await sess.ws_connect(url, ssl=False)
    s = Session(ws)
    # wait until the shell answers a command
    for _ in range(3):
        at = s.mark()
        await s.send("echo RDY$((40+2))\r")
        if await s.until(r"RDY42", since=at, timeout=6):
            return s
    await s.close()
    return None


async def run(ctx):
    rc, out = await ctx.run_py(SETUP)
    ids = _result(out)
    ctx.ok("keybar: test users and a terminal service created", rc == 0 and bool(ids), out[-300:])
    if not ids:
        return
    service_id = ids["service"]

    async def page_checks(label, session, url):
        async with session.get(url) as r:
            body = await r.text()
            status = r.status
        ctx.ok(f"keybar: {label} page loads", status == 200, f"status {status}")
        if status != 200:
            return
        ctx.ok(f"keybar: {label} page carries the key bar, the toggle and the paste dialog",
               'id="keybar"' in body and 'id="keybar-toggle"' in body and 'id="paste-dialog"' in body
               and all(f'data-key="{k}"' in body for k in ("esc", "tab", "left", "right", "up", "down"))
               and 'data-mod="ctrl"' in body and 'data-mod="alt"' in body, "")
        ctx.ok(f"keybar: {label} page loads terminal.js v6 after the key helper, host-key script kept",
               "terminal.js?v=7" in body and "terminal-keybar.js?v=2" in body and "hostkey.js?v=1" in body
               and body.index("terminal-keybar.js") < body.index("terminal.js?v=7")
               and body.index("hostkey.js") < body.index("terminal.js?v=7"), "")
        ctx.ok(f"keybar: {label} page has no unreplaced template fields", "{{" not in body, "")
        ctx.ok(f"keybar: {label} page keeps the bar hidden until the script turns it on",
               re.search(r"\.keybar\s*\{[^}]*display:\s*none", body) is not None, "")

    # ---- user connection page (non-admin) -------------------------------
    async with ctx.http() as s:
        resp = await ctx.login(s, USER, USER_PW)
        ctx.ok("keybar: non-admin login", resp.status == 200, f"status {resp.status}")
        if resp.status == 200:
            async with s.post(f"{ctx.base_url}/api/connections", json={
                    "name": "kb ssh", "type": "ssh", "host": GOOD_HOST, "port": 22,
                    "config": {"username": "u"}}) as r:
                body = await r.json()
                conn_id = body.get("id")
                ctx.ok("keybar: ssh connection created", r.status in (200, 201) and bool(conn_id), f"{r.status} {body}")
            if conn_id:
                await page_checks("user SSH connection", s, f"{ctx.base_url}/terminal/connect?connection={conn_id}")

    # ---- admin pages, static files and the PTY ----------------------------
    async with ctx.http() as s:
        resp = await ctx.login(s, ADMIN, ADMIN_PW)
        if resp.status != 200:
            ctx.ok("keybar: admin login", False, f"status {resp.status}")
            return
        await page_checks("local shell", s, f"{ctx.base_url}/terminal/local")
        await page_checks("terminal service", s, f"{ctx.base_url}/terminal/{service_id}")

        served = {}
        for name in ("terminal.js", "terminal-keybar.js"):
            async with s.get(f"{ctx.base_url}/static/js/{name}?v=cur") as r:
                served[name] = await r.text()
                ctx.ok(f"keybar: /static/js/{name} is served",
                       r.status == 200 and "javascript" in r.headers.get("Content-Type", ""),
                       f"{r.status} {r.headers.get('Content-Type')}")
        ctx.ok("keybar: terminal.js still hands the host-key prompt its reconnect",
               "HostKey.prompt(data, { onAccepted: () => reconnect() })" in served["terminal.js"], "")
        ctx.ok("keybar: the bar choice is read and written inside try/catch",
               "try { return window.localStorage.getItem" in served["terminal.js"]
               and "try { window.localStorage.setItem" in served["terminal.js"], "")

        # ---- the sequences the served helper makes, then a real shell ----
        node = shutil.which("node")
        if not node:
            ctx.skip("keybar: key sequences and the PTY session", "node is not installed")
            return
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "keys.js").write_text(KEYS_JS)
            (Path(tmp) / "terminal-keybar.js").write_text(served["terminal-keybar.js"])
            proc = await asyncio.create_subprocess_exec(
                node, str(Path(tmp) / "keys.js"), str(Path(tmp) / "terminal-keybar.js"),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), 30)
        line = next((l for l in out.decode().splitlines() if l.startswith("KEYS=")), "")
        keys = json.loads(line[5:]) if line else None
        ctx.ok("keybar: the served helper produces the expected sequences",
               keys == {"ctrl_c": "\x03", "tab": "\t", "up_normal": "\x1b[A", "up_app": "\x1bOA",
                        "alt_x": "\x1bx", "multi": True, "single": False,
                        "paste_clean": "ls; id\tok\r\n", "report_focus": True, "report_key": False},
               out.decode()[-200:])
        ctx.ok("keybar: the served page script cleans pasted text, keeps sticky keys through terminal reports "
               "and refocuses only when the terminal had focus",
               "TermKeys.sanitizePaste(text)" in served["terminal.js"]
               and "TermKeys.isTerminalReport(data)" in served["terminal.js"]
               and "if (hadFocus) term.focus();" in served["terminal.js"]
               and "term.paste(text)" not in served["terminal.js"], "")
        if not keys:
            return

        shell = await _open(ctx, s, service_id)
        ctx.ok("keybar: a bash session behind /ws/terminal/<id> answers commands", shell is not None, "")
        if shell is None:
            return
        try:
            # Ctrl+C interrupts a running command
            await shell.send("sleep 30\r")
            await asyncio.sleep(0.6)
            t0 = time.monotonic()
            await shell.send(keys["ctrl_c"])
            at = shell.mark()
            await shell.send("echo INT$?\r")
            m = await shell.until(r"INT130", since=at, timeout=8)
            ctx.ok("keybar: Ctrl+C interrupts a running command (status 130, prompt back within seconds)",
                   m is not None and time.monotonic() - t0 < 8, shell.text[-200:])

            # Tab completes a file name
            at = shell.mark()
            await shell.send("ls kbcomplete_")
            await asyncio.sleep(0.4)
            await shell.send(keys["tab"])
            m = await shell.until(re.escape(COMPLETE_NAME), since=at, timeout=6)
            ctx.ok("keybar: Tab completes a file name", m is not None, shell.text[at:][-200:])
            clean = await drop_line(shell, keys["ctrl_c"])     # drop the half-typed line
            ctx.ok("keybar: Ctrl+C drops a half-typed line and the shell is back at a clean prompt",
                   clean, shell.text[-200:])

            # Up arrow recalls history, in normal and in application cursor mode
            for label, seq in (("normal", keys["up_normal"]), ("application", keys["up_app"])):
                at = shell.mark()
                await shell.send(f"echo HI$((7000+{731 if label == 'normal' else 732}))\r")
                want = "HI7731" if label == "normal" else "HI7732"
                first = await shell.until(want, since=at, timeout=6)
                at2 = shell.mark()
                await shell.send(seq)
                await asyncio.sleep(0.3)
                await shell.send("\r")
                # the typed command contains "$((", so only the run prints the number again
                again = await shell.until(want, since=at2, timeout=6)
                ctx.ok(f"keybar: up arrow ({label} cursor mode) recalls the last command in bash",
                       first is not None and again is not None, shell.text[at2:][-200:])
        finally:
            await shell.close()
