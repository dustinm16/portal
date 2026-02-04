"""Terminal plugin - Web-based PTY terminal.

Security Note:
    This plugin spawns PTY processes on the server. The shell runs with the
    same permissions as the Portal Gateway server process. For security:
    - Use proper authentication and authorization
    - Consider running the server as a non-root user
    - Use SSH plugin for connecting to remote systems
"""

import asyncio
import fcntl
import os
import pty
import pwd
import select
import signal
import struct
import termios
import logging
import json
import errno

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

        # Build environment
        env = os.environ.copy()
        env.update(config.get("env", {}))
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env["LANG"] = env.get("LANG", "en_US.UTF-8")

        cols = config.get("cols", 80)
        rows = config.get("rows", 24)

        logger.info(f"Starting terminal session for user {user_id}: shell={shell}, cwd={working_dir}")

        # Validate shell exists and is executable
        if not os.path.isfile(shell):
            logger.error(f"Shell not found: {shell}")
            await ws.send_json({"type": "error", "message": f"Shell not found: {shell}"})
            return

        if not os.access(shell, os.X_OK):
            logger.error(f"Shell not executable: {shell}")
            await ws.send_json({"type": "error", "message": f"Shell not executable: {shell}"})
            return

        # Validate working directory
        if not os.path.isdir(working_dir):
            logger.warning(f"Working directory not found, using /tmp: {working_dir}")
            working_dir = "/tmp"

        master_fd = None
        pid = None

        try:
            # Create PTY
            master_fd, slave_fd = pty.openpty()
            logger.debug(f"PTY created: master={master_fd}, slave={slave_fd}")

            # Set initial window size
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

            # Fork process
            pid = os.fork()

            if pid == 0:
                # Child process
                try:
                    os.close(master_fd)

                    # Create new session and set controlling terminal
                    os.setsid()

                    # Set controlling terminal
                    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

                    # Redirect stdin/stdout/stderr to slave PTY
                    os.dup2(slave_fd, 0)
                    os.dup2(slave_fd, 1)
                    os.dup2(slave_fd, 2)

                    if slave_fd > 2:
                        os.close(slave_fd)

                    # Change to working directory
                    os.chdir(working_dir)

                    # Execute shell
                    os.execvpe(shell, [shell, "-l"], env)
                except Exception as e:
                    os._exit(1)
            else:
                # Parent process
                os.close(slave_fd)
                logger.debug(f"Shell process started: pid={pid}")

                # Set non-blocking
                flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

                # Send connected message
                await ws.send_json({
                    "type": "connected",
                    "message": f"Terminal ready ({shell})"
                })

                try:
                    await self._terminal_loop(ws, master_fd, pid, user_id)
                except Exception as e:
                    logger.error(f"Terminal loop error for user {user_id}: {e}")

        except Exception as e:
            logger.error(f"Failed to create terminal for user {user_id}: {e}")
            await ws.send_json({"type": "error", "message": f"Failed to create terminal: {e}"})
        finally:
            # Cleanup
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass

            if pid is not None and pid > 0:
                try:
                    # Try graceful termination first
                    os.kill(pid, signal.SIGTERM)
                    # Give it a moment
                    await asyncio.sleep(0.1)
                    # Force kill if still running
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

                try:
                    os.waitpid(pid, os.WNOHANG)
                except OSError:
                    pass

            logger.info(f"Terminal session ended for user {user_id}")

    async def _terminal_loop(
        self,
        ws: web.WebSocketResponse,
        master_fd: int,
        pid: int,
        user_id: int
    ) -> None:
        """Main terminal I/O loop."""
        loop = asyncio.get_event_loop()

        logger.debug(f"Starting terminal loop for user {user_id}, pid={pid}")

        # Create tasks for reading from PTY and WebSocket
        pty_reader = asyncio.create_task(
            self._read_pty(master_fd, ws, loop),
            name=f"pty_reader_{user_id}"
        )
        ws_reader = asyncio.create_task(
            self._read_ws(ws, master_fd, pid),
            name=f"ws_reader_{user_id}"
        )

        try:
            # Wait for either task to complete (usually means connection closed)
            done, pending = await asyncio.wait(
                [pty_reader, ws_reader],
                return_when=asyncio.FIRST_COMPLETED
            )

            # Check for exceptions in completed tasks
            for task in done:
                try:
                    exc = task.exception()
                    if exc:
                        logger.error(f"Terminal task error for user {user_id}: {exc}")
                except asyncio.CancelledError:
                    pass

        except asyncio.CancelledError:
            logger.debug(f"Terminal loop cancelled for user {user_id}")
        except Exception as e:
            logger.error(f"Terminal loop error for user {user_id}: {e}")
        finally:
            # Cancel any pending tasks
            for task in [pty_reader, ws_reader]:
                if not task.done():
                    task.cancel()

            # Wait for cancellation to complete
            try:
                await asyncio.gather(pty_reader, ws_reader, return_exceptions=True)
            except Exception:
                pass

            logger.debug(f"Terminal loop ended for user {user_id}")

    async def _read_pty(
        self,
        master_fd: int,
        ws: web.WebSocketResponse,
        loop: asyncio.AbstractEventLoop
    ) -> None:
        """Read from PTY and send to WebSocket."""
        logger.debug(f"PTY reader started for fd={master_fd}")

        while not ws.closed:
            try:
                # Wait for data with select in thread pool
                readable, _, _ = await loop.run_in_executor(
                    None,
                    lambda: select.select([master_fd], [], [], 0.1)
                )

                if not readable:
                    # Check if process is still alive
                    continue

                # Read available data
                try:
                    data = os.read(master_fd, 16384)  # Larger buffer for better throughput
                    if data:
                        if not ws.closed:
                            await ws.send_str(data.decode("utf-8", errors="replace"))
                    else:
                        # EOF - PTY closed
                        logger.debug("PTY EOF received")
                        break
                except OSError as e:
                    if e.errno == errno.EIO:
                        # Expected when PTY closes
                        logger.debug("PTY closed (EIO)")
                    else:
                        logger.debug(f"PTY read OSError: {e}")
                    break

            except asyncio.CancelledError:
                logger.debug("PTY reader cancelled")
                break
            except Exception as e:
                logger.error(f"PTY read error: {e}")
                break

        logger.debug("PTY reader ended")

    async def _read_ws(
        self,
        ws: web.WebSocketResponse,
        master_fd: int,
        pid: int
    ) -> None:
        """Read from WebSocket and write to PTY."""
        logger.debug(f"WebSocket reader started for fd={master_fd}")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        msg_type = data.get("type")

                        if msg_type == "input":
                            # Terminal input
                            text = data.get("data", "")
                            if text:
                                try:
                                    written = os.write(master_fd, text.encode("utf-8"))
                                    logger.debug(f"Wrote {written} bytes to PTY")
                                except OSError as e:
                                    if e.errno == errno.EIO:
                                        logger.debug("PTY write failed - process likely exited")
                                        break
                                    raise

                        elif msg_type == "resize":
                            # Terminal resize
                            cols = data.get("cols", 80)
                            rows = data.get("rows", 24)
                            logger.debug(f"Resizing terminal to {cols}x{rows}")
                            winsize = struct.pack("HHHH", rows, cols, 0, 0)
                            try:
                                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                                # Send SIGWINCH to notify process of resize
                                os.kill(pid, signal.SIGWINCH)
                            except OSError as e:
                                logger.debug(f"Resize failed: {e}")

                        elif msg_type == "ping":
                            # Heartbeat
                            pass

                    except json.JSONDecodeError:
                        # Plain text input (backwards compatibility)
                        try:
                            os.write(master_fd, msg.data.encode("utf-8"))
                        except OSError:
                            break

                elif msg.type == WSMsgType.BINARY:
                    # Binary data - write directly
                    try:
                        os.write(master_fd, msg.data)
                    except OSError:
                        break

                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    logger.debug(f"WebSocket {msg.type.name}")
                    break

        except asyncio.CancelledError:
            logger.debug("WebSocket reader cancelled")
        except Exception as e:
            logger.error(f"WebSocket reader error: {e}")

        logger.debug("WebSocket reader ended")

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
