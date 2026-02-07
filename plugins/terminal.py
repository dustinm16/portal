"""Terminal plugin - Web-based PTY terminal.

Security Note:
    This plugin spawns PTY processes on the server. The shell runs with the
    same permissions as the Open Relay Portal server process. For security:
    - Use proper authentication and authorization
    - Consider running the server as a non-root user
    - Use SSH plugin for connecting to remote systems
"""

import asyncio
import fcntl
import os
import pty
import pwd
import re
import select
import signal
import struct
import termios
import logging
import json
import errno
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from aiohttp import web, WSMsgType

from .base import PluginBase, PluginInfo, ServiceTarget
from . import register_plugin
from config import Config
from database import db

logger = logging.getLogger("portal.plugins.terminal")

# Terminal capability query patterns and their immediate responses.
# Shells like fish send these queries and wait for a response from the terminal.
# In a WebSocket-proxied terminal, the round-trip through the browser is too slow
# (fish times out after 2 seconds). We intercept these server-side and respond
# immediately, stripping the queries from the data sent to xterm.js to prevent
# duplicate responses.
_TERM_QUERIES = [
    # DA1 - Primary Device Attributes: ESC [ c  or  ESC [ 0 c
    (re.compile(r'\x1b\[0?c'), '\x1b[?1;2c'),
    # DA2 - Secondary Device Attributes: ESC [ > c  or  ESC [ > 0 c
    (re.compile(r'\x1b\[>0?c'), '\x1b[>0;276;0c'),
    # DSR - Device Status Report: ESC [ 5 n
    (re.compile(r'\x1b\[5n'), '\x1b[0n'),
]


def _intercept_terminal_queries(data: str, write_fd: int) -> str:
    """Intercept terminal capability queries and respond immediately.

    Returns the data with query sequences stripped out.
    Writes responses directly to the PTY/stdin fd.
    """
    for pattern, response in _TERM_QUERIES:
        if pattern.search(data):
            try:
                os.write(write_fd, response.encode())
            except OSError:
                pass
            data = pattern.sub('', data)
    return data


class AsciicastRecorder:
    """Records terminal session in asciicast v2 format.

    Asciicast v2 format:
    - First line: JSON header with version, width, height, timestamp
    - Subsequent lines: [time, type, data] events
    """

    def __init__(self, user_id: int, service_id: int, cols: int = 80, rows: int = 24):
        self.user_id = user_id
        self.service_id = service_id
        self.cols = cols
        self.rows = rows
        self.start_time = time.time()
        self.events: list[tuple[float, str, str]] = []
        self.recording_id: Optional[int] = None
        self.filename: Optional[str] = None
        self._active = False

    async def start(self) -> int:
        """Start recording and create database entry."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = f"rec_{self.user_id}_{self.service_id}_{timestamp}.cast"

        self.recording_id = await db.create_recording(
            user_id=self.user_id,
            service_id=self.service_id,
            filename=self.filename,
            format="asciicast"
        )
        self._active = True
        logger.info(f"Recording started: {self.filename} (id={self.recording_id})")
        return self.recording_id

    def record_output(self, data: str) -> None:
        """Record terminal output."""
        if not self._active:
            return
        elapsed = time.time() - self.start_time
        self.events.append((elapsed, "o", data))

    def record_input(self, data: str) -> None:
        """Record terminal input (optional, for debugging)."""
        if not self._active:
            return
        elapsed = time.time() - self.start_time
        self.events.append((elapsed, "i", data))

    async def finish(self) -> None:
        """Finalize recording and write to file."""
        if not self._active or not self.filename:
            return

        self._active = False
        duration = time.time() - self.start_time

        # Ensure recordings directory exists
        recordings_dir = Path(Config.RECORDINGS_DIR)
        recordings_dir.mkdir(parents=True, exist_ok=True)

        filepath = recordings_dir / self.filename

        # Write asciicast v2 format
        header = {
            "version": 2,
            "width": self.cols,
            "height": self.rows,
            "timestamp": int(self.start_time),
            "env": {"TERM": "xterm-256color"}
        }

        try:
            with open(filepath, "w") as f:
                f.write(json.dumps(header) + "\n")
                for event in self.events:
                    f.write(json.dumps(list(event)) + "\n")

            size = filepath.stat().st_size
            await db.update_recording(self.recording_id, size, duration)
            logger.info(f"Recording saved: {self.filename} ({size} bytes, {duration:.1f}s)")
        except Exception as e:
            logger.error(f"Failed to save recording {self.filename}: {e}")


@register_plugin
class TerminalPlugin(PluginBase):
    """Web terminal plugin using PTY."""

    info = PluginInfo(
        name="terminal",
        display_name="Web Terminal",
        description="Browser-based terminal with PTY support",
        version="1.1.0",
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
                },
                "recording": {
                    "type": "boolean",
                    "description": "Enable session recording (asciicast format)",
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

        # Initialize session recording if enabled
        recorder: Optional[AsciicastRecorder] = None
        recording_enabled = config.get("recording", False) and Config.RECORDING_ENABLED
        if recording_enabled:
            recorder = AsciicastRecorder(user_id, target.id, cols, rows)
            await recorder.start()
            logger.info(f"Session recording enabled for user {user_id}, service {target.id}")

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
                    "message": f"Terminal ready ({shell})",
                    "recording": recording_enabled
                })

                try:
                    await self._terminal_loop(ws, master_fd, pid, user_id, recorder)
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

            # Finalize recording if enabled
            if recorder:
                await recorder.finish()

            logger.info(f"Terminal session ended for user {user_id}")

    async def _terminal_loop(
        self,
        ws: web.WebSocketResponse,
        master_fd: int,
        pid: int,
        user_id: int,
        recorder: Optional[AsciicastRecorder] = None
    ) -> None:
        """Main terminal I/O loop."""
        loop = asyncio.get_event_loop()

        logger.debug(f"Starting terminal loop for user {user_id}, pid={pid}")

        # Create tasks for reading from PTY and WebSocket
        pty_reader = asyncio.create_task(
            self._read_pty(master_fd, ws, loop, recorder),
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
        loop: asyncio.AbstractEventLoop,
        recorder: Optional[AsciicastRecorder] = None
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
                        decoded = data.decode("utf-8", errors="replace")
                        # Intercept terminal queries (DA1, DA2, DSR) and respond
                        # immediately to avoid shell timeouts (e.g. fish 2s DA1 wait)
                        decoded = _intercept_terminal_queries(decoded, master_fd)
                        if decoded and not ws.closed:
                            await ws.send_str(decoded)
                        # Record output if recording is enabled
                        if recorder and decoded:
                            recorder.record_output(decoded)
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
