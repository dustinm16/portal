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


class RecordingsDirRefused(OSError):
    """The recordings folder failed the safety check (recording_paths)."""


def prepare_recordings_dir(path: str) -> Path:
    """Create the recordings directory (owner only) and tighten an existing one.

    Raises RecordingsDirRefused, without touching the folder, when it is a
    dangerous location or holds anything besides recordings.
    """
    reason = recording_paths.check(path)
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
            directory = prepare_recordings_dir(Config.RECORDINGS_DIR)
            filepath = directory / filename
            db.live_recording_files.add(filename)  # before the file exists
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW
            self._fd = os.open(filepath, flags, 0o600)
            header = self._header_line()
            os.write(self._fd, header)
            self.size = len(header)
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



def recording_wanted(config) -> bool:
    """True when a connection's config switches recording on and the portal allows it.

    Only a real boolean true counts (a stored "false" string must not turn it on).
    Recording is off per connection by default.
    """
    return isinstance(config, dict) and config.get("recording") is True and bool(Config.RECORDING_ENABLED)


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
