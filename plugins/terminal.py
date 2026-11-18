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

from config import ALLOWED_SHELLS as _ALLOWED_SHELLS
import re
import secrets
import select
import shutil
import signal
import stat
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
from database import db, RECORDING_FILE_EXTENSION

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


async def _move_to_own_scope(pid: int, user_id: int) -> Optional[str]:
    """Move a freshly forked shell into its own transient systemd scope.

    Without this the shell, and anything it daemonizes (tmux, screen, nohup
    jobs), lives in the portal's service cgroup and is killed whenever the
    portal restarts. Returns the scope name, or None when the host has no
    systemd, the call is refused, or it times out; the terminal then simply
    runs inside the portal's cgroup as before.
    """
    if not Config.TERMINAL_OWN_SCOPE or not os.path.isdir("/run/systemd/system"):
        return None
    busctl = shutil.which("busctl")
    if not busctl:
        return None
    scope = f"portal-terminal-{pid}-{int(time.time())}.scope"
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            busctl, "call", "--system",
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager", "StartTransientUnit",
            "ssa(sv)a(sa(sv))", scope, "fail",
            "3",
            "PIDs", "au", "1", str(pid),
            "Description", "s", f"Open Relay Portal web terminal (user {user_id})",
            "CollectMode", "s", "inactive-or-failed",
            "0",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, err = await asyncio.wait_for(proc.communicate(), timeout=5)
        if proc.returncode != 0:
            logger.warning(
                f"Could not create terminal scope for user {user_id}: "
                f"{err.decode(errors='replace').strip()[:200]}"
            )
            return None
        # StartTransientUnit only queues a job; wait until the pid has moved.
        for _ in range(100):
            try:
                with open(f"/proc/{pid}/cgroup") as f:
                    if scope in f.read():
                        return scope
            except OSError:
                return None
            await asyncio.sleep(0.02)
        logger.warning(f"Terminal scope {scope} was created but pid {pid} did not move into it")
    except asyncio.TimeoutError:
        logger.warning(f"Timed out creating terminal scope for user {user_id}")
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except (ProcessLookupError, OSError):
                pass
    except Exception as e:
        logger.warning(f"Could not create terminal scope for user {user_id}: {e}")
    return None


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


RECORDING_MAX_BYTES = 50 * 1024 * 1024  # a recording stops growing at this size; the session goes on
RECORDING_TRUNCATED_NOTE = "recording truncated: size limit reached"
_TRUNCATION_RESERVE = 128  # room kept free below the cap for the closing marker line


def prepare_recordings_dir(path: str) -> Path:
    """Create the recordings directory (owner only) and tighten an existing one."""
    directory = Path(path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def tighten_recording_files(path: str) -> int:
    """Set mode 0600 on the regular files directly inside the recordings directory.

    Recordings written by older versions are 0644. A symlink is never followed
    (it is not a regular file, and the open refuses it), nothing outside the
    directory is touched and subdirectories are not entered. Returns the number
    of files whose mode was changed.
    """
    try:
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return 0
    changed = 0
    try:
        with os.scandir(dir_fd) as entries:
            names = [e.name for e in entries]
        for name in names:
            try:
                # O_NONBLOCK so that a FIFO planted here cannot block the open
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            except OSError:
                continue  # a symlink (ELOOP), unreadable or vanished
            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) != 0o600:
                    os.fchmod(fd, 0o600)
                    changed += 1
            except OSError as e:
                logger.warning(f"Could not tighten the mode of recording file {name}: {e}")
            finally:
                os.close(fd)
    finally:
        os.close(dir_fd)
    return changed


class AsciicastRecorder:
    """Records terminal output in asciicast v2 format, appending as it goes.

    Asciicast v2 format:
    - First line: JSON header with version, width, height, timestamp
    - Subsequent lines: [time, type, data] events, time in seconds since start

    The file is created with mode 0600 inside RECORDINGS_DIR (0700) when the
    session starts and every output chunk is appended as one complete line, so
    the file is a valid recording at any moment. Only output is recorded, never
    keystrokes. Past max_bytes the recording stops and the session carries on.
    A recorder that cannot write (disk full, directory not writable) turns
    itself off instead of affecting the terminal.
    """

    def __init__(self, user_id: int, service_id, cols: int = 80, rows: int = 24,
                 max_bytes: Optional[int] = None):
        self.user_id = user_id
        self.service_id = service_id
        self.cols = cols
        self.rows = rows
        self.max_bytes = RECORDING_MAX_BYTES if max_bytes is None else max_bytes
        self.start_time = time.time()
        self._t0 = time.monotonic()
        self.recording_id: Optional[int] = None
        self.filename: Optional[str] = None
        self.size = 0
        self.truncated = False
        self._fd: Optional[int] = None
        self._active = False

    def _header_line(self) -> bytes:
        header = {
            "version": 2,
            "width": self.cols,
            "height": self.rows,
            "timestamp": int(self.start_time),
            "env": {"TERM": "xterm-256color"},
        }
        return (json.dumps(header) + "\n").encode("utf-8")

    def _close_fd(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    async def start(self) -> Optional[int]:
        """Create the file and the database row. Returns None when recording is not possible."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_service = re.sub(r"[^A-Za-z0-9]", "", str(self.service_id)) or "x"
        filename = f"rec_{self.user_id}_{safe_service}_{timestamp}_{secrets.token_hex(4)}{RECORDING_FILE_EXTENSION}"
        try:
            directory = prepare_recordings_dir(Config.RECORDINGS_DIR)
            filepath = directory / filename
            db.live_recording_files.add(filename)  # before the file exists
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW
            self._fd = os.open(filepath, flags, 0o600)
            header = self._header_line()
            os.write(self._fd, header)
            self.size = len(header)
        except OSError as e:
            logger.error(f"Cannot start recording: {e}")
            self._close_fd()
            db.live_recording_files.discard(filename)
            return None
        self.filename = filename
        try:
            self.recording_id = await db.create_recording(
                user_id=self.user_id,
                service_id=self.service_id,
                filename=filename,
                size=self.size,
                format="asciicast"
            )
        except Exception as e:
            logger.error(f"Cannot register recording {filename}: {e}")
            self._close_fd()
            try:
                os.unlink(filepath)
            except OSError:
                pass
            db.live_recording_files.discard(filename)
            return None
        db.live_recording_ids.add(self.recording_id)
        self._active = True
        logger.info(f"Recording started: {filename} (id={self.recording_id})")
        return self.recording_id

    def record_output(self, data: str) -> None:
        """Append one output event to the file."""
        if not self._active or self._fd is None:
            return
        elapsed = round(time.monotonic() - self._t0, 6)
        line = (json.dumps([elapsed, "o", data]) + "\n").encode("utf-8")
        if self.size + len(line) + _TRUNCATION_RESERVE > self.max_bytes:
            self._truncate(elapsed)
            return
        try:
            os.write(self._fd, line)
            self.size += len(line)
        except OSError as e:
            logger.error(f"Recording {self.filename} stopped, write failed: {e}")
            self._active = False
            self._close_fd()

    def _truncate(self, elapsed: float) -> None:
        """Stop at the size limit and close the file with a marker event ("m"),
        so a viewer can tell the recording was cut. The marker fits in the room
        kept free below the cap; if it does not, the file just ends."""
        self.truncated = True
        self._active = False
        marker = (json.dumps([elapsed, "m", RECORDING_TRUNCATED_NOTE]) + "\n").encode("utf-8")
        try:
            if self._fd is not None and self.size + len(marker) <= self.max_bytes:
                os.write(self._fd, marker)
                self.size += len(marker)
        except OSError as e:
            logger.warning(f"Recording {self.filename}: could not write the truncation marker: {e}")
        self._close_fd()
        logger.info(f"Recording {self.filename} reached the size limit of {self.max_bytes} bytes and stopped")

    async def finish(self) -> None:
        """Close the file and store the final size and duration."""
        if self.recording_id is None or not self.filename:
            return
        recording_id, self.recording_id = self.recording_id, None
        self._active = False
        self._close_fd()
        duration = time.monotonic() - self._t0
        try:
            await db.update_recording(recording_id, self.size, duration)
            logger.info(f"Recording saved: {self.filename} ({self.size} bytes, {duration:.1f}s)")
        except Exception as e:
            logger.error(f"Failed to save recording {self.filename}: {e}")
        finally:
            # The session is over: retention may now treat the recording like any other.
            db.live_recording_ids.discard(recording_id)
            db.live_recording_files.discard(self.filename)


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
        if shell not in _ALLOWED_SHELLS:
            logger.warning(f"Rejected disallowed shell: {shell}")
            await ws.send_json({"type": "error", "message": f"Shell not allowed: {shell}"})
            return
        working_dir = os.path.expanduser(config.get("working_dir", "~"))

        # Build environment — filter dangerous keys from config overrides
        _BLOCKED_ENV_PREFIXES = ("LD_", "DYLD_", "_RLD", "LIBPATH", "SHLIB_PATH")
        _BLOCKED_ENV_KEYS = {
            "BASH_ENV", "ENV", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT",
            "ZDOTDIR", "PYTHONPATH", "NODE_OPTIONS", "IFS",
        }
        env = os.environ.copy()
        for k, v in (config.get("env") or {}).items():
            if k.upper() in _BLOCKED_ENV_KEYS:
                continue
            if any(k.upper().startswith(p) for p in _BLOCKED_ENV_PREFIXES):
                continue
            env[k] = v
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
            if await recorder.start() is None:
                recorder = None
                recording_enabled = False
            else:
                logger.info(f"Session recording enabled for user {user_id}, service {target.id}")

        master_fd = None
        pid = None
        gate_w = None

        try:
            # Create PTY
            master_fd, slave_fd = pty.openpty()
            logger.debug(f"PTY created: master={master_fd}, slave={slave_fd}")

            # Set initial window size
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

            # The child waits on this pipe before exec'ing the shell, so the
            # parent can move it into its own systemd scope first and nothing
            # the shell starts is left behind in the portal's cgroup.
            gate_r, gate_w = os.pipe()

            # Fork process
            try:
                pid = os.fork()
            except OSError:
                os.close(gate_r)
                raise

            if pid == 0:
                # Child process
                try:
                    os.close(master_fd)
                    os.close(gate_w)
                    # Until exec this is still a copy of the portal: detach it
                    # from the portal's signal handling so a SIGTERM aimed at
                    # this child cannot trigger the server's shutdown handler.
                    signal.set_wakeup_fd(-1)
                    signal.signal(signal.SIGTERM, signal.SIG_DFL)
                    signal.signal(signal.SIGINT, signal.SIG_DFL)
                    # Python ignores these at startup and "ignored" survives
                    # exec; give the shell normal pipe behaviour.
                    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
                    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)

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

                    # Wait for the parent (returns on its write or on EOF)
                    try:
                        os.read(gate_r, 1)
                    except OSError:
                        pass
                    os.close(gate_r)

                    # Execute shell
                    os.execvpe(shell, [shell, "-l"], env)
                except Exception as e:
                    os._exit(1)
            else:
                # Parent process
                os.close(slave_fd)
                os.close(gate_r)
                try:
                    scope = await _move_to_own_scope(pid, user_id)
                finally:
                    # Write as well as close: a terminal forked meanwhile holds
                    # a copy of this write end until it execs, which would
                    # otherwise delay the EOF the child is waiting for.
                    try:
                        os.write(gate_w, b"x")
                    except OSError:
                        pass
                    os.close(gate_w)
                    gate_w = None
                logger.debug(f"Shell process started: pid={pid}, scope={scope}")

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
            await ws.send_json({"type": "error", "message": "Failed to create terminal"})
        finally:
            # Cleanup
            if gate_w is not None:
                try:
                    os.close(gate_w)
                except OSError:
                    pass
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
