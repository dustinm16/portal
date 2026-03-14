"""SSH plugin - SSH over WebSocket."""

import asyncio
import logging
import json
from typing import Optional

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

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
                    "enum": ["password", "key", "agent"],
                    "description": "Authentication method",
                    "default": "password"
                },
                "private_key": {
                    "type": "string",
                    "description": "Private key content (for key auth)"
                },
                "private_key_path": {
                    "type": "string",
                    "description": "Path to private key file"
                },
                "known_hosts": {
                    "type": "string",
                    "enum": ["strict", "trust_first", "ignore"],
                    "description": "Host key verification",
                    "default": "trust_first"
                },
                "shell": {
                    "type": "string",
                    "description": "Remote shell to use (e.g. /bin/bash, /usr/bin/fish)",
                    "default": ""
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
            "known_hosts": None if config.get("known_hosts") == "ignore" else (),
        }

        if auth_method == "key":
            key_content = config.get("private_key")
            key_path = config.get("private_key_path")
            if key_content:
                connect_opts["client_keys"] = [asyncssh.import_private_key(key_content)]
            elif key_path:
                connect_opts["client_keys"] = [key_path]
        elif auth_method == "agent":
            connect_opts["agent_forwarding"] = True

        # Track terminal size from client resize messages
        term_cols, term_rows = 80, 24

        # Wait for password if needed
        password = None
        if auth_method == "password":
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
            async with asyncssh.connect(**connect_opts) as conn:
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
                    await ws.send_json({
                        "type": "connected",
                        "host": host,
                        "username": connect_opts["username"]
                    })

                    await self._ssh_loop(ws, process)

        except asyncssh.Error as e:
            logger.warning(f"SSH connection failed for user {user_id}: {e}")
            await ws.send_json({"type": "error", "message": "SSH connection failed"})
        except Exception as e:
            logger.error(f"SSH connection error for user {user_id}: {e}")
            await ws.send_json({"type": "error", "message": "Connection failed"})

    async def _ssh_loop(self, ws: web.WebSocketResponse, process) -> None:
        """Handle SSH I/O."""
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
                        await ws.send_str(data)
            except Exception as e:
                logger.debug(f"SSH stdout ended: {e}")

        async def read_stderr():
            try:
                while not process.stderr.at_eof():
                    data = await process.stderr.read(65536)
                    if data:
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
