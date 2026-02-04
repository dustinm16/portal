"""Terminal plugin - Web-based PTY terminal."""

import asyncio
import fcntl
import os
import pty
import select
import struct
import termios
import logging
import json

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin

logger = logging.getLogger("portal.plugins.terminal")


@register_plugin
class TerminalPlugin(PluginBase):
    """Web terminal plugin using PTY."""

    info = PluginInfo(
        name="terminal",
        display_name="Web Terminal",
        description="Browser-based terminal with PTY support",
        version="1.0.0",
        icon="terminal",
        protocols=["websocket"],
        config_schema={
            "type": "object",
            "properties": {
                "shell": {
                    "type": "string",
                    "description": "Shell to execute",
                    "default": "/bin/bash"
                },
                "working_dir": {
                    "type": "string",
                    "description": "Initial working directory",
                    "default": "~"
                },
                "env": {
                    "type": "object",
                    "description": "Environment variables",
                    "default": {}
                },
                "cols": {
                    "type": "integer",
                    "description": "Initial terminal columns",
                    "default": 80
                },
                "rows": {
                    "type": "integer",
                    "description": "Initial terminal rows",
                    "default": 24
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
        """Handle terminal WebSocket connection."""
        config = target.config
        shell = config.get("shell", "/bin/bash")
        working_dir = os.path.expanduser(config.get("working_dir", "~"))
        env = {**os.environ, **config.get("env", {})}
        env["TERM"] = "xterm-256color"

        cols = config.get("cols", 80)
        rows = config.get("rows", 24)

        logger.info(f"Starting terminal session for user {user_id}: {shell}")

        # Create PTY
        master_fd, slave_fd = pty.openpty()

        # Set initial window size
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

        # Fork process
        pid = os.fork()

        if pid == 0:
            # Child process
            os.close(master_fd)
            os.setsid()
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(slave_fd)
            os.chdir(working_dir)
            os.execvpe(shell, [shell], env)
        else:
            # Parent process
            os.close(slave_fd)

            # Set non-blocking
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            try:
                await self._terminal_loop(ws, master_fd, pid)
            finally:
                os.close(master_fd)
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                except OSError:
                    pass
                logger.info(f"Terminal session ended for user {user_id}")

    async def _terminal_loop(
        self,
        ws: web.WebSocketResponse,
        master_fd: int,
        pid: int
    ) -> None:
        """Main terminal I/O loop."""
        loop = asyncio.get_event_loop()

        # Create tasks for reading from PTY and WebSocket
        pty_reader = asyncio.create_task(self._read_pty(master_fd, ws, loop))
        ws_reader = asyncio.create_task(self._read_ws(ws, master_fd))

        try:
            # Wait for either task to complete (usually means connection closed)
            done, pending = await asyncio.wait(
                [pty_reader, ws_reader],
                return_when=asyncio.FIRST_COMPLETED
            )
            # Check for exceptions in completed tasks
            for task in done:
                if task.exception():
                    logger.error(f"Terminal task error: {task.exception()}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Terminal loop error: {e}")
        finally:
            pty_reader.cancel()
            ws_reader.cancel()
            # Wait for cancellation to complete
            try:
                await asyncio.gather(pty_reader, ws_reader, return_exceptions=True)
            except:
                pass

    async def _read_pty(
        self,
        master_fd: int,
        ws: web.WebSocketResponse,
        loop: asyncio.AbstractEventLoop
    ) -> None:
        """Read from PTY and send to WebSocket."""
        while not ws.closed:
            try:
                # Wait for data with select in thread pool
                readable, _, _ = await loop.run_in_executor(
                    None,
                    lambda: select.select([master_fd], [], [], 0.1)
                )

                if not readable:
                    continue

                # Read available data
                try:
                    data = os.read(master_fd, 4096)
                    if data:
                        if not ws.closed:
                            await ws.send_str(data.decode("utf-8", errors="replace"))
                    else:
                        # EOF - PTY closed
                        logger.debug("PTY EOF received")
                        break
                except OSError as e:
                    logger.debug(f"PTY read OSError: {e}")
                    break

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"PTY read error: {e}")
                break

    async def _read_ws(self, ws: web.WebSocketResponse, master_fd: int) -> None:
        """Read from WebSocket and write to PTY."""
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)

                    if data.get("type") == "input":
                        # Terminal input
                        text = data.get("data", "")
                        os.write(master_fd, text.encode("utf-8"))

                    elif data.get("type") == "resize":
                        # Terminal resize
                        cols = data.get("cols", 80)
                        rows = data.get("rows", 24)
                        winsize = struct.pack("HHHH", rows, cols, 0, 0)
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

                except json.JSONDecodeError:
                    # Plain text input (backwards compatibility)
                    os.write(master_fd, msg.data.encode("utf-8"))

            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check if shell is available."""
        shell = target.config.get("shell", "/bin/bash")
        if os.path.exists(shell) and os.access(shell, os.X_OK):
            return {"healthy": True, "message": f"Shell available: {shell}"}
        return {"healthy": False, "message": f"Shell not found: {shell}"}

    def get_client_assets(self) -> dict:
        return {
            "js": ["xterm.min.js", "xterm-addon-fit.min.js"],
            "css": ["xterm.min.css"],
            "html": "terminal.html"
        }
