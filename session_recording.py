"""Session recording shared by the terminal and SSH plugins.

One recorder writes an asciicast v2 file (output and resize events only, never
keystrokes) into RECORDINGS_DIR and keeps one row per recording in the database.
The folder is 0700, the files 0600, a recording stops growing at a size cap and
retention removes old ones (database.cleanup_old_recordings).

Playback side: open_recording() opens a row's file for reading and proves it is a
plain file inside the recordings folder (no symlink, no path separator in the
name), so a row can never be used to read or remove anything else.
"""

import json
import logging
import os
import asyncio
import re
import secrets
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import Config
from database import db, RECORDING_FILE_EXTENSION
import recording_paths

logger = logging.getLogger("portal.recording")

RECORDING_MAX_BYTES = 50 * 1024 * 1024  # a recording stops growing at this size; the session goes on
RECORDING_TRUNCATED_NOTE = "recording truncated: size limit reached"
_TRUNCATION_RESERVE = 128  # room kept free below the cap for the closing marker line


# Disk budget. The total is a running count (header and every written line, reconciled by one
# walk of the folder at startup, after the retention pass and after an administrator's delete),
# so starting a session never walks the folder. Sessions that run at the same time can overshoot
# the budget by up to RECORDING_MAX_BYTES each. An older recording is never deleted to make room.
DEFAULT_MAX_TOTAL_MB = 2048          # setting recording_max_total_mb; 0 = no limit
FREE_FLOOR_BYTES = 1024 ** 3         # refuse under min(1 GiB, 5 percent of the filesystem) free
FREE_FLOOR_FRACTION = 0.05
WARN_INTERVAL_SECONDS = 600          # one warning per reason per ten minutes
_total_bytes = 0
_warned: dict = {}


def recordings_total_bytes() -> int:
    return _total_bytes


def _scan_total(path: str) -> int:
    """Sum of the sizes of the recording files directly inside the folder (a symlink is not
    followed; subfolders are not entered)."""
    total = 0
    try:
        with os.scandir(path) as entries:
            for e in entries:
                if not e.name.endswith(RECORDING_FILE_EXTENSION):
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    total += st.st_size
    except OSError:
        return 0
    return total


async def reconcile_total(path: Optional[str] = None) -> int:
    """Recount the folder (one walk, off the event loop) and store the result as the running total."""
    global _total_bytes
    folder = path or Config.RECORDINGS_DIR
    _total_bytes = await asyncio.to_thread(_scan_total, folder)
    return _total_bytes


def _free_and_total(path: str) -> tuple:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize


def _warn_once(reason: str, message: str) -> None:
    now = time.monotonic()
    last = _warned.get(reason)
    if last is not None and now - last < WARN_INTERVAL_SECONDS:
        return
    _warned[reason] = now
    logger.warning(message)


async def budget_refusal(directory) -> Optional[str]:
    """The reason a new recording must not start (budget used up, or too little free space), else None."""
    try:
        raw = await db.get_setting("recording_max_total_mb")
        max_mb = int(raw) if raw is not None else DEFAULT_MAX_TOTAL_MB
        if max_mb < 0:
            max_mb = DEFAULT_MAX_TOTAL_MB
    except (TypeError, ValueError):
        max_mb = DEFAULT_MAX_TOTAL_MB
    if max_mb and _total_bytes >= max_mb * 1024 * 1024:
        return (f"the recordings folder holds {_total_bytes // (1024 * 1024)} MB, "
                f"at the limit of {max_mb} MB (setting recording_max_total_mb)")
    try:
        free, total = _free_and_total(str(directory))
    except OSError:
        return None  # cannot tell; the write itself fails safely if the disk is full
    floor = min(FREE_FLOOR_BYTES, int(total * FREE_FLOOR_FRACTION))
    if free < floor:
        return f"only {free // (1024 * 1024)} MB are free on the disk of the recordings folder (floor {floor // (1024 * 1024)} MB)"
    return None


class RecordingsDirRefused(OSError):
    """The recordings folder failed the safety check (recording_paths)."""


def prepare_recordings_dir(path: str, cached: bool = False) -> Path:
    """Create the recordings directory (owner only) and tighten an existing one.

    Raises RecordingsDirRefused, without touching the folder, when it is a
    dangerous location or holds anything besides recordings. With cached=True a folder
    that passed once in this run is not read again (the start of a session uses it).
    """
    reason = (recording_paths.check_verified if cached else recording_paths.check)(path)
    if reason:
        raise RecordingsDirRefused(f"{path} cannot be used for recordings: {reason}")
    directory = Path(path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def tighten_recording_files(path: str) -> int:
    """Set mode 0600 on the regular files directly inside the recordings directory.

    Recordings written by older versions are 0644. A symlink is never followed
    (it is not a regular file, and the open refuses it), nothing outside the
    directory is touched and subdirectories are not entered. Returns the number
    of files whose mode was changed. A folder that fails the safety check
    (recording_paths) is left alone.
    """
    if recording_paths.check(path):
        return 0
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


def _bounded_size(value, default: int) -> int:
    """A terminal dimension from a client: an integer from 1 to 1000, else the default."""
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return n if 1 <= n <= 1000 else default


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
                 max_bytes: Optional[int] = None, *, connection_id: Optional[int] = None,
                 connection_name: Optional[str] = None, kind: str = "terminal"):
        self.user_id = user_id
        # A recording belongs to an admin service (service_id) or to a user
        # connection (connection_id), never both.
        self.service_id = service_id
        self.connection_id = connection_id
        self.connection_name = connection_name
        self.kind = kind
        self.cols = _bounded_size(cols, 80)
        self.rows = _bounded_size(rows, 24)
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
        # The clock starts when the file exists, so an event time is seconds into the session.
        self.start_time = time.time()
        self._t0 = time.monotonic()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        which = self.service_id if self.service_id is not None else (
            f"c{self.connection_id}" if self.connection_id is not None else "x")
        safe_service = re.sub(r"[^A-Za-z0-9]", "", str(which)) or "x"
        filename = f"rec_{self.user_id}_{safe_service}_{timestamp}_{secrets.token_hex(4)}{RECORDING_FILE_EXTENSION}"
        try:
            directory = prepare_recordings_dir(Config.RECORDINGS_DIR, cached=True)
            refusal = await budget_refusal(directory)
            if refusal:
                _warn_once("budget", f"Recording refused, the session goes on unrecorded: {refusal}")
                return None
            filepath = directory / filename
            db.live_recording_files.add(filename)  # before the file exists
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW
            self._fd = os.open(filepath, flags, 0o600)
            header = self._header_line()
            os.write(self._fd, header)
            self.size = len(header)
            _count(self.size)
        except RecordingsDirRefused:
            return None  # already logged once by recording_paths
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
                format="asciicast",
                connection_id=self.connection_id,
                connection_name=self.connection_name,
                kind=self.kind,
            )
        except Exception as e:
            logger.error(f"Cannot register recording {filename}: {e}")
            self._close_fd()
            try:
                os.unlink(filepath)
                _count(-self.size)
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
        self._append("o", data)

    def record_resize(self, cols, rows) -> None:
        """Append a resize event ("r", "COLSxROWS"). The size comes from the client, so it is
        coerced to a bounded integer pair; anything else is ignored."""
        try:
            c, r = int(cols), int(rows)
        except (TypeError, ValueError, OverflowError):
            return
        if not (1 <= c <= 1000 and 1 <= r <= 1000):
            return
        self._append("r", f"{c}x{r}")

    def _append(self, kind: str, data: str) -> None:
        if not self._active or self._fd is None:
            return
        elapsed = round(time.monotonic() - self._t0, 6)
        line = (json.dumps([elapsed, kind, data]) + "\n").encode("utf-8")
        if self.size + len(line) + _TRUNCATION_RESERVE > self.max_bytes:
            self._truncate(elapsed)
            return
        try:
            os.write(self._fd, line)
            self.size += len(line)
            _count(len(line))
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
                _count(len(marker))
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



def _count(n: int) -> None:
    global _total_bytes
    _total_bytes = max(0, _total_bytes + n)


_TAIL_WINDOW = 64 * 1024  # how much of the end of a file is read to find its last event


def _last_event_time(fd: int) -> tuple:
    """(file size, time of the last complete event or 0.0) of an open recording, reading only the
    tail: the window doubles until a complete event line is found or the whole file was read. A
    last line without its newline (a write cut off by the restart) and lines that are not events
    are ignored."""
    size = os.fstat(fd).st_size
    window = max(64, _TAIL_WINDOW)
    while True:
        start = max(0, size - window)
        os.lseek(fd, start, os.SEEK_SET)
        data = b""
        while len(data) < size - start:
            chunk = os.read(fd, size - start - len(data))
            if not chunk:
                break
            data += chunk
        lines = data.split(b"\n")
        lines.pop()                      # what follows the last newline is empty or cut off
        if start > 0 and lines:
            lines.pop(0)                 # the first line of the window may be a partial one
        for raw in reversed(lines):
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if (isinstance(event, list) and len(event) >= 2 and isinstance(event[0], (int, float))
                    and not isinstance(event[0], bool) and isinstance(event[1], str)):
                return size, max(0.0, float(event[0]))
        if start == 0:
            return size, 0.0
        window *= 4


async def finish_interrupted() -> int:
    """Close off recordings that a restart cut short, at startup.

    A row with no end (duration 0, not live) whose file exists gets the size of the file, the
    time of the file's last complete event as its duration, and is marked interrupted. A row
    whose file is missing or refused is left as it is (nothing is deleted). Returns the number
    of rows closed."""
    closed = 0
    for row in await db.list_unfinished_recordings():
        if row["id"] in db.live_recording_ids:
            continue
        try:
            fd = open_recording(row["filename"])
        except (RecordingFileMissing, RecordingFileRefused) as e:
            logger.warning(f"Interrupted recording {row['id']} not closed off: {e}")
            continue
        try:
            size, duration = await asyncio.to_thread(_last_event_time, fd)
        except OSError as e:
            logger.warning(f"Interrupted recording {row['id']} could not be read: {e}")
            continue
        finally:
            os.close(fd)
        if await db.mark_recording_interrupted(row["id"], size, round(duration, 6)):
            closed += 1
    if closed:
        logger.info(f"Closed off {closed} recording(s) cut short by a restart")
    return closed


def recording_wanted(config) -> bool:
    """True when a connection's config switches recording on and the portal allows it.

    On means exactly True, the integer 1, the text "1" or the text "true" in any case;
    everything else (false, 0, "false", "yes", " true", 1.0, 2, a list) is off. Recording is
    off per connection by default.
    """
    if not isinstance(config, dict) or not Config.RECORDING_ENABLED:
        return False
    return _flag_on(config.get("recording"))


def _flag_on(value) -> bool:
    if value is True:
        return True
    if type(value) is int:
        return value == 1
    return isinstance(value, str) and value.lower() in ("1", "true")


def recorder_for(target, user_id: int, cols: int, rows: int, kind: str) -> Optional[AsciicastRecorder]:
    """A recorder for a plugin target, or None when the target is not one that is recorded.

    An admin service has an integer id; a user connection (own or shared) has
    "user-conn-<n>". The user is the person at the keyboard, so a grantee of a
    shared connection is recorded under the grantee's own id. Anything else
    (the server's local terminal) is never recorded.
    """
    tid = getattr(target, "id", None)
    name = str(getattr(target, "name", "") or "")[:200] or None
    if isinstance(tid, int) and not isinstance(tid, bool) and tid > 0:
        return AsciicastRecorder(user_id, tid, cols, rows, connection_name=name, kind=kind)
    if isinstance(tid, str):
        m = re.fullmatch(r"user-conn-(\d{1,18})", tid)
        if m:
            return AsciicastRecorder(user_id, None, cols, rows, connection_id=int(m.group(1)),
                                     connection_name=name, kind=kind)
    return None


class RecordingFileMissing(OSError):
    """The recording's file is not there."""


class RecordingFileRefused(OSError):
    """The row names something that is not a plain file inside the recordings folder."""


def plain_recording_name(name) -> bool:
    """A bare file name with the recording extension: no folder part, no NUL, not . or .."""
    return (isinstance(name, str) and bool(name) and name not in (".", "..")
            and "/" not in name and "\\" not in name and "\x00" not in name
            and name.endswith(RECORDING_FILE_EXTENSION))


def open_recording(filename, recordings_dir: Optional[str] = None) -> int:
    """Open a recording file for reading and return the descriptor.

    Raises RecordingFileMissing when it does not exist and RecordingFileRefused for
    everything unsafe: a refused recordings folder, a name with a path in it, a
    symlink, anything that is not a regular file, or a file that does not resolve
    inside the (symlink-resolved) recordings folder. The caller closes the descriptor.
    """
    path = recordings_dir or Config.RECORDINGS_DIR
    if recording_paths.check(path):
        raise RecordingFileRefused("recordings folder refused")
    if not plain_recording_name(filename):
        raise RecordingFileRefused("unsafe file name")
    directory = os.path.realpath(path)
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except FileNotFoundError:
        raise RecordingFileMissing(filename)
    except OSError as e:
        raise RecordingFileRefused(str(e))
    try:
        try:
            # O_NOFOLLOW: a symlink in place of the file is refused, never followed.
            # O_NONBLOCK: a FIFO planted here cannot block the open.
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            raise RecordingFileMissing(filename)
        except OSError as e:
            raise RecordingFileRefused(f"cannot open: {e.strerror or e}")
    finally:
        os.close(dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RecordingFileRefused("not a regular file")
        proc = f"/proc/self/fd/{fd}"
        if os.path.exists("/proc/self/fd"):
            resolved = os.path.realpath(proc)
            if not resolved.startswith(directory.rstrip(os.sep) + os.sep):
                raise RecordingFileRefused("file is outside the recordings folder")
    except BaseException:
        os.close(fd)
        raise
    return fd


def remove_recording_file(filename, recordings_dir: Optional[str] = None) -> bool:
    """Remove a recording's file; True when it was removed or already gone, False when the
    name is not a plain recording name (nothing is touched then). A symlink in its place is
    removed itself, never followed. Raises OSError when the removal fails."""
    path = recordings_dir or Config.RECORDINGS_DIR
    if not plain_recording_name(filename) or recording_paths.check(path):
        return False
    try:
        dir_fd = os.open(os.path.realpath(path), os.O_RDONLY | os.O_DIRECTORY)
    except FileNotFoundError:
        return True
    try:
        os.unlink(filename, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    finally:
        os.close(dir_fd)
    return True
