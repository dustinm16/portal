"""SSH plugin - SSH over WebSocket."""

import asyncio
import logging
import json
from typing import Optional

from aiohttp import web, WSMsgType

import sshpass_rules
from hostkeys import HostKeyRefused, connect_verified, policy_for
from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin
from session_recording import AsciicastRecorder, recorder_for, recording_wanted

logger = logging.getLogger("portal.plugins.ssh")

from config import ALLOWED_SHELLS as _ALLOWED_SHELLS

# NOTE: Unlike the local terminal plugin, we do NOT intercept DA1/DA2/DSR
# queries server-side for SSH connections. Server-side interception fails
# for SSH because:
#   1. Escape sequences may be split across SSH channel data chunks
#   2. process.stdin.write() goes through asyncssh buffer + network, adding
#      unreliable latency vs the local PTY's synchronous os.write()
#   3. Stripping queries prevents xterm.js from responding as a fallback
# Instead, queries pass through to xterm.js which responds natively.
# The WebSocket round-trip (~100-200ms) is well within fish's 2s timeout.

# Optional asyncssh import
try:
    import asyncssh
    HAS_ASYNCSSH = True
except ImportError:
    HAS_ASYNCSSH = False
    logger.warning("asyncssh not installed - SSH plugin disabled")


@register_plugin
class SSHPlugin(PluginBase):
    """SSH over WebSocket plugin."""

    info = PluginInfo(
        name="ssh",
        display_name="SSH Terminal",
        description="SSH connection over WebSocket for browser access",
        version="1.0.0",
        icon="terminal-box",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "required": ["host"],
            "properties": {
                "host": {
                    "type": "string",
                    "description": "SSH server hostname or IP"
                },
                "port": {
                    "type": "integer",
                    "description": "SSH port",
                    "default": 22
                },
                "username": {
                    "type": "string",
                    "description": "SSH username"
                },
                "auth_method": {
                    "type": "string",
                    "enum": ["password", "key"],
                    "description": "Authentication method",
                    "default": "password"
                },
                "private_key": {
                    "writeOnly": True,
                    "type": "string",
                    "description": "Private key content (for key auth)"
                },
                "private_key_path": {
                    "writeOnly": True,
                    "type": "string",
                    "description": "Path to private key file"
                },
                "host_key_ignore": {
                    "type": "boolean",
                    "description": "Do not verify host key (not recommended: the server's identity is then not checked)",
                    "default": False
                },
                "shell": {
                    "type": "string",
                    "description": "Remote shell to use (e.g. /bin/bash, /usr/bin/fish)",
                    "default": ""
                },
                "recording": {
                    "type": "boolean",
                    "description": "Record the session output (asciicast format; input is never recorded)",
                    "default": False
                }
            }
        }
    )

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle SSH WebSocket connection."""
        if not HAS_ASYNCSSH:
            await ws.send_json({
                "type": "error",
                "message": "SSH support not available (asyncssh not installed)"
            })
            return

        config = target.config
        host = config.get("host", target.host)
        port = config.get("port", target.port or 22)
        username = config.get("username")

        logger.info(f"SSH connection for user {user_id}: {username}@{host}:{port}")

        # Prepare auth options
        auth_method = config.get("auth_method", "password")
        connect_opts = {
            "host": host,
            "port": port,
            "username": username,
        }
        # The host key is checked during the key exchange (before any
        # credential is sent) against the pin stored in the config; see hostkeys.
        pinned_key, ignore_key = policy_for(config)

        # Only the credential stored with this connection is ever offered; the
        # portal's own keys, ssh-agent and ssh config are never used (see
        # hostkeys.locked_client_options).
        if auth_method == "agent":
            await ws.send_json({"type": "error", "message": "SSH agent authentication is not supported"})
            return
        if auth_method == "key":
            key_content = config.get("private_key")
            key_path = config.get("private_key_path")
            if key_content:
                connect_opts["client_keys"] = [asyncssh.import_private_key(key_content)]
            elif key_path:
                if config.get("_pinned_hosts"):
                    # A user connection: a path would be read from the portal
                    # server's disk, with the portal's own file access.
                    await ws.send_json({"type": "error",
                                        "message": "Key file paths are not allowed here; paste the private key instead"})
                    return
                connect_opts["client_keys"] = [key_path]

        # Track terminal size from client resize messages
        term_cols, term_rows = 80, 24

        # Wait for password if needed
        password = None
        stored_pw = sshpass_rules.terminal_password(config) if auth_method == "password" else None
        if stored_pw is not None and ignore_key:
            # A host whose key is not checked never gets the stored password.
            await ws.send_json({"type": "error", "message":
                                "A stored password is only used with a verified host key"})
            return
        if stored_pw is not None and not username:
            stored_pw = None            # nobody to log in as: ask (the prompt takes a username)
        if stored_pw is not None:
            # No prompt. The host key is checked during the key exchange, before the
            # password goes out; an unpinned or changed key refuses the connect with
            # nothing sent (hostkeys.connect_verified) and the owner is shown it.
            connect_opts["password"] = stored_pw
        elif auth_method == "password":
            needs_username = not username
            await ws.send_json({
                "type": "auth_required",
                "method": "password",
                "needs_username": needs_username
            })

            # Loop to skip non-auth messages (e.g. resize sent on WS open)
            # Timeout after 60s to prevent resource exhaustion from unauthenticated connections
            try:
                while True:
                    msg = await asyncio.wait_for(ws.receive(), timeout=60)
                    if msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                        return
                    if msg.type == WSMsgType.TEXT:
                        try:
                            data = json.loads(msg.data)
                        except json.JSONDecodeError:
                            continue
                        if data.get("type") == "auth":
                            password = data.get("password")
                            if data.get("username"):
                                connect_opts["username"] = data["username"]
                            break
                        elif data.get("type") == "resize":
                            term_cols = data.get("cols", 80)
                            term_rows = data.get("rows", 24)
            except asyncio.TimeoutError:
                logger.warning(f"SSH auth timeout for user {user_id}: no credentials received within 60s")
                await ws.send_json({"type": "error", "message": "Authentication timed out"})
                return

            if password:
                connect_opts["password"] = password
            else:
                await ws.send_json({"type": "error", "message": "Password required"})
                return

        try:
            # User connections arrive with the already policy-checked addresses
            # in _pinned_hosts (set by the connection handler); dial those,
            # trying each in turn on connect-level failures only.
            conn, _seen = await connect_verified(
                config.get("_pinned_hosts") or [host],
                {**connect_opts, "connect_timeout": 15},
                pinned=pinned_key, ignore=ignore_key, timeout=None)
            async with conn:
                # Build process options - only pass command when explicitly set
                proc_opts = {
                    "term_type": "xterm-256color",
                    "term_size": (term_cols, term_rows),
                }
                shell_cmd = config.get("shell", "").strip()
                if shell_cmd:
                    if shell_cmd not in _ALLOWED_SHELLS:
                        logger.warning(f"Rejected disallowed shell: {shell_cmd}")
                        await ws.send_json({"type": "error", "message": f"Shell not allowed: {shell_cmd}"})
                        return
                    proc_opts["command"] = shell_cmd
                async with conn.create_process(**proc_opts) as process:
                    # Recording starts here, once the shell is up (so a failed login leaves
                    # no empty recording and the clock starts with the session). It belongs
                    # to the person at the keyboard: a grantee of a shared connection is
                    # recorded under the grantee's own id.
                    recorder: Optional[AsciicastRecorder] = None
                    if recording_wanted(config):
                        recorder = recorder_for(target, user_id, term_cols, term_rows, "ssh")
                        if recorder is not None and await recorder.start() is None:
                            recorder = None
                    try:
                        # The server says whether this session is recorded, in the frame that
                        # opens it, before any output is sent or recorded.
                        await ws.send_json({
                            "type": "connected",
                            "host": host,
                            "username": connect_opts["username"],
                            "recording": recorder is not None
                        })

                        await self._ssh_loop(ws, process, recorder)
                    finally:
                        if recorder is not None:
                            await recorder.finish()

        except HostKeyRefused:
            # Not a failure to report here: the caller shows the fingerprint
            # to the user and decides who may accept it.
            raise
        except asyncssh.Error as e:
            logger.warning(f"SSH connection failed for user {user_id}: {e}")
            await ws.send_json({"type": "error", "message": "SSH connection failed"})
        except Exception as e:
            logger.error(f"SSH connection error for user {user_id}: {e}")
            await ws.send_json({"type": "error", "message": "Connection failed"})

    async def _ssh_loop(self, ws: web.WebSocketResponse, process,
                        recorder: Optional[AsciicastRecorder] = None) -> None:
        """Handle SSH I/O. Only what the remote sends (and resizes) is recorded, never input."""
        async def read_stdout():
            try:
                # Use read(n) not async-for: the async iterator calls readline()
                # which buffers until \n. Escape sequences like DA1 queries
                # don't end with newlines and would be delayed, causing fish
                # shell to time out waiting for terminal capability responses.
                # read(n) with n>0 returns as soon as any data is available.
                # read(-1) would block until EOF — don't use that.
                while not process.stdout.at_eof():
                    data = await process.stdout.read(65536)
                    if data:
                        if recorder is not None:
                            recorder.record_output(data)
                        await ws.send_str(data)
            except Exception as e:
                logger.debug(f"SSH stdout ended: {e}")

        async def read_stderr():
            try:
                while not process.stderr.at_eof():
                    data = await process.stderr.read(65536)
                    if data:
                        if recorder is not None:
                            recorder.record_output(data)
                        await ws.send_str(data)
            except Exception as e:
                logger.debug(f"SSH stderr ended: {e}")

        async def read_ws():
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        if data.get("type") == "input":
                            try:
                                process.stdin.write(data.get("data", ""))
                            except Exception:
                                break
                        elif data.get("type") == "resize":
                            process.change_terminal_size(
                                data.get("cols", 80),
                                data.get("rows", 24)
                            )
                            if recorder is not None:
                                recorder.record_resize(data.get("cols", 80), data.get("rows", 24))
                    except json.JSONDecodeError:
                        try:
                            process.stdin.write(msg.data)
                        except Exception:
                            break
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break

        tasks = [
            asyncio.ensure_future(read_stdout()),
            asyncio.ensure_future(read_stderr()),
            asyncio.ensure_future(read_ws()),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check SSH connectivity."""
        if not HAS_ASYNCSSH:
            return {"healthy": False, "message": "asyncssh not installed"}

        host = target.config.get("host", target.host)
        port = target.config.get("port", target.port or 22)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            return {"healthy": True, "message": f"SSH port open: {host}:{port}"}
        except Exception as e:
            return {"healthy": False, "message": f"Cannot reach {host}:{port}: {e}"}

    def get_client_assets(self) -> dict:
        return {
            "js": ["xterm.min.js", "xterm-addon-fit.min.js"],
            "css": ["xterm.min.css"],
            "html": "terminal.html"
        }
