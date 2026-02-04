"""SSH plugin - SSH over WebSocket."""

import asyncio
import logging
import json
from typing import Optional

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.ssh")

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

        # Wait for password if needed
        password = None
        if auth_method == "password":
            await ws.send_json({"type": "auth_required", "method": "password"})

            msg = await ws.receive()
            if msg.type == WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get("type") == "auth":
                    password = data.get("password")
                    if data.get("username"):
                        connect_opts["username"] = data["username"]

            if password:
                connect_opts["password"] = password
            else:
                await ws.send_json({"type": "error", "message": "Password required"})
                return

        try:
            async with asyncssh.connect(**connect_opts) as conn:
                async with conn.create_process(
                    term_type="xterm-256color",
                    term_size=(80, 24)
                ) as process:
                    await ws.send_json({
                        "type": "connected",
                        "host": host,
                        "username": connect_opts["username"]
                    })

                    await self._ssh_loop(ws, process)

        except asyncssh.Error as e:
            logger.error(f"SSH error: {e}")
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception as e:
            logger.error(f"Connection error: {e}")
            await ws.send_json({"type": "error", "message": f"Connection failed: {e}"})

    async def _ssh_loop(self, ws: web.WebSocketResponse, process) -> None:
        """Handle SSH I/O."""
        async def read_stdout():
            try:
                async for data in process.stdout:
                    if data:
                        await ws.send_str(data)
            except Exception as e:
                logger.debug(f"SSH stdout ended: {e}")

        async def read_stderr():
            try:
                async for data in process.stderr:
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
                            process.stdin.write(data.get("data", ""))
                        elif data.get("type") == "resize":
                            process.change_terminal_size(
                                data.get("cols", 80),
                                data.get("rows", 24)
                            )
                    except json.JSONDecodeError:
                        process.stdin.write(msg.data)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break

        await asyncio.gather(
            read_stdout(),
            read_stderr(),
            read_ws(),
            return_exceptions=True
        )

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
