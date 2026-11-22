"""Watching a VOD chunk in the browser: the playback cache and the pieces around it.

Pure helpers with no dependency on the server module, so they can be tested on their own.

Design (the server module wires these to the routes, the SFTP storage and ffmpeg):

* A chunk is an MKV on the owner's own SFTP storage. To play it the portal pulls it over the
  pinned SFTP connection, asks ffprobe what is in it, and remuxes it (no transcode) into an MP4
  with the index first (-movflags +faststart), which a browser can start without downloading it
  all and can seek with Range requests.
* The result lives in a byte-capped LRU cache folder (0700, files 0600) beside the VOD staging
  folder. An entry is keyed by owner, the storage it came from, the path, and the remote size and
  modification time, so a chunk that changed on the remote is never served from an old entry.
* The cap counts everything in the folder: finished entries plus the space a running job has
  reserved for its pulled source and its output. A job that does not fit evicts the least
  recently used entries first; a chunk that can never fit is refused.
* An index file (index.json) records the entries; at start the folder is reconciled with it and
  anything the index does not know (an interrupted job, a half written file) is removed.
* ffmpeg and ffprobe are given the file by local path only, the demuxer is forced to matroska
  (so no concat, playlist or other demuxer that names further files can be chosen by the file's
  content) and the protocol whitelist is "file".
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import time
from typing import Optional

logger = logging.getLogger("portal")

# Setting vod_play_cache_mb: megabytes, 0 switches playback off.
DEFAULT_CACHE_MB = 512
MAX_CACHE_MB = 1_000_000

MARKER_NAME = ".portal_vod_play_cache"
INDEX_NAME = "index.json"
WORK_NAME = "work"
_ENTRY_RE = re.compile(r"^[0-9a-f]{32}\.mp4$")
_CHUNK_RE = re.compile(r"^chunk_(\d+)\.mkv$", re.IGNORECASE)

MAX_PATH_CHARS = 1024
MAX_SEGMENTS = 12
OUTPUT_SLACK = 256 * 1024          # added to the output size limit (headers of a tiny file)
_COPY_BLOCK = 1024 * 1024


# ---------------------------------------------------------------------------
# Setting
# ---------------------------------------------------------------------------

def cache_cap_bytes(raw) -> int:
    """The playback cache cap in bytes from the setting (megabytes, fractions allowed). 0 = off.
    An unreadable or negative value gives the default."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        mb = float(DEFAULT_CACHE_MB)
    else:
        try:
            mb = float(raw)
        except (TypeError, ValueError):
            mb = float(DEFAULT_CACHE_MB)
        if mb != mb or mb < 0 or mb == float("inf"):
            mb = float(DEFAULT_CACHE_MB)
    return int(min(mb, MAX_CACHE_MB) * 1024 * 1024)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def chunk_path_from_url(name: str) -> Optional[str]:
    """The remote chunk path (relative to the storage root, ending .mkv) a play URL names, or None.

    The URL is the path My VODs lists, with ".mp4" appended. The same rules as the listing: no
    empty segment, no segment that starts with a dot (so no "." or ".."), no absolute path, no
    backslash, no control character, and the file is an .mkv.
    """
    if not isinstance(name, str) or not name.endswith(".mp4"):
        return None
    path = name[:-4]
    if not path or len(path) > MAX_PATH_CHARS:
        return None
    if path.startswith("/") or "\\" in path or re.search(r"[\x00-\x1f\x7f]", path):
        return None
    parts = path.split("/")
    if len(parts) > MAX_SEGMENTS:
        return None
    for part in parts:
        if not part or part.startswith("."):
            return None
    if not path.lower().endswith(".mkv"):
        return None
    return path


def chunk_number(filename: str) -> Optional[int]:
    m = _CHUNK_RE.match(filename)
    return int(m.group(1)) if m else None


def storage_ident(storage: dict) -> str:
    """Names the storage a chunk came from (host, port, user, folder) without keeping those in the index."""
    raw = "|".join(str(storage.get(k) or "") for k in ("host", "username")) + \
          f"|{storage.get('port') or 22}|{str(storage.get('remote_path') or '').rstrip('/')}"
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def entry_key(owner: int, ident: str, path: str, size: int, mtime: int) -> str:
    raw = json.dumps([int(owner), ident, path, int(size), int(mtime)], ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# ffprobe and ffmpeg
# ---------------------------------------------------------------------------

def ffprobe_argv(path: str, fmt: str = "matroska") -> list:
    return ["ffprobe", "-v", "error", "-protocol_whitelist", "file", "-f", fmt,
            "-show_format", "-show_streams", "-of", "json", "file:" + path]


def remux_argv(src: str, out: str, size_limit: int) -> list:
    """ffmpeg arguments: first video and first audio stream copied, nothing else carried over."""
    return ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-n",
            "-protocol_whitelist", "file", "-f", "matroska", "-i", "file:" + src,
            "-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn",
            "-map_metadata", "-1", "-map_chapters", "-1",
            "-c", "copy", "-movflags", "+faststart", "-fs", str(int(size_limit)),
            "-f", "mp4", "file:" + out]


def output_limit(source_size: int) -> int:
    """The most an MP4 made from a source of this size may take (a copy is about the same size)."""
    return int(source_size) + int(source_size) // 5 + OUTPUT_SLACK


def job_reserve(source_size: int) -> int:
    """What a job needs on disk at its peak: the pulled source and the output being written."""
    return int(source_size) + output_limit(source_size)


def download_only_message(why: str) -> str:
    return f"This chunk cannot be played in the browser ({why}). Download it instead."


def verdict(info: dict) -> tuple:
    """(playable, reason) from ffprobe's JSON. Playable: H.264 video (8 bit 4:2:0) with AAC or
    MP3 audio, or no audio."""
    streams = info.get("streams") if isinstance(info, dict) else None
    if not isinstance(streams, list):
        return False, "the file could not be read"
    video = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"]
    audio = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "audio"]
    if not video:
        return False, "it has no video"
    v = video[0]
    if v.get("codec_name") != "h264":
        return False, f"video codec {str(v.get('codec_name') or 'unknown')[:20]}"
    if v.get("pix_fmt") not in ("yuv420p", "yuvj420p"):
        return False, f"picture format {str(v.get('pix_fmt') or 'unknown')[:20]}"
    if audio:
        a = audio[0]
        if a.get("codec_name") not in ("aac", "mp3"):
            return False, f"audio codec {str(a.get('codec_name') or 'unknown')[:20]}"
    return True, ""


def top_level_boxes(path: str, limit: int = 64) -> list:
    """Types of the top-level boxes of an MP4 file, in file order."""
    boxes = []
    size_total = os.path.getsize(path)
    with open(path, "rb") as fh:
        pos = 0
        while pos + 8 <= size_total and len(boxes) < limit:
            fh.seek(pos)
            head = fh.read(16)
            if len(head) < 8:
                break
            size = int.from_bytes(head[:4], "big")
            kind = head[4:8].decode("latin-1")
            if size == 1:
                if len(head) < 16:
                    break
                size = int.from_bytes(head[8:16], "big")
            elif size == 0:
                size = size_total - pos
            if size < 8:
                break
            boxes.append(kind)
            pos += size
    return boxes


def index_first(path: str) -> bool:
    """True when the moov box comes before the media data (the file starts without the whole download)."""
    boxes = top_level_boxes(path)
    return "moov" in boxes and "mdat" in boxes and boxes.index("moov") < boxes.index("mdat")


# ---------------------------------------------------------------------------
# The cache folder
# ---------------------------------------------------------------------------

def refusal_reason(path: str, project_root: Optional[str] = None, forbidden_roots: tuple = (),
                   other_data_dirs: tuple = ()) -> Optional[str]:
    """Why *path* must not be the cache folder, or None. A folder that exists must be empty or carry
    the cache marker: the folder is cleaned up (strays removed), so it has to be the cache's own.
    *other_data_dirs* are folders of live data (the VOD staging folder, the recordings folder): the cache
    must not be one of them, hold one or lie inside one, whatever the folder is (the portal's own
    default included), because the cache is cleaned up and a rollback empties it."""
    import vod_staging
    real = os.path.realpath(path)
    for root in forbidden_roots:
        if root and vod_staging._inside(real, os.path.realpath(str(root))):
            return f"it is inside {root}, which the web server serves"
    for other in other_data_dirs:
        if not other:
            continue
        other_real = os.path.realpath(str(other))
        if vod_staging._inside(real, other_real) or vod_staging._inside(other_real, real):
            return f"it overlaps {other}, which holds recordings or chunks waiting to upload"
    own_default = bool(project_root) and real == os.path.join(os.path.realpath(project_root), "data", "vod_play_cache")
    reason = vod_staging.dangerous_reason(real, project_root, allow_temp=own_default)
    if reason:
        return reason
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"it cannot be read: {e.strerror or e}"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return "it is a symbolic link or not a directory"
    if st.st_uid != os.geteuid():
        return "it belongs to another user"
    try:
        has_marker = stat.S_ISREG(os.lstat(os.path.join(path, MARKER_NAME)).st_mode)
        nonempty = any(True for _ in os.scandir(path))
    except FileNotFoundError:
        has_marker = False
        nonempty = any(True for _ in os.scandir(path))
    except OSError as e:
        return f"it cannot be read: {e.strerror or e}"
    if nonempty and not has_marker and not own_default:
        return f"it is not empty and was not made by the portal (no {MARKER_NAME} file)"
    return None


def prepare_dir(path: str, project_root: Optional[str] = None, forbidden_roots: tuple = (),
                other_data_dirs: tuple = ()) -> None:
    """Create the cache folder (0700) with its marker, or raise ValueError."""
    path = os.path.abspath(path)
    reason = refusal_reason(path, project_root, forbidden_roots, other_data_dirs)
    if reason:
        raise ValueError(f"{path} cannot be used: {reason}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    if stat.S_IMODE(os.lstat(path).st_mode) != 0o700:
        os.chmod(path, 0o700)
    try:
        fd = os.open(os.path.join(path, MARKER_NAME), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("Created by the portal for the browser playback cache of VOD chunks.\n")


def _remove_path(path: str) -> int:
    """Remove a file or a folder of ours without following links. Returns the bytes freed."""
    freed = 0
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    try:
        if stat.S_ISDIR(st.st_mode):
            for root, _dirs, files in os.walk(path):
                for name in files:
                    try:
                        freed += os.lstat(os.path.join(root, name)).st_size
                    except OSError:
                        pass
            shutil.rmtree(path, ignore_errors=True)
        else:
            freed = st.st_size if stat.S_ISREG(st.st_mode) else 0
            os.unlink(path)
    except OSError as e:
        logger.warning(f"VOD play cache: could not remove {os.path.basename(path)}: {e}")
    return freed


class PlayCache:
    """Byte-capped LRU cache of remuxed chunks. All calls run on the event loop thread."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.entries: dict = {}       # key -> {file, size, owner, path, ident, rsize, rmtime, used}
        self.reserved = 0             # bytes jobs have reserved for their source and output
        self._cond: Optional[asyncio.Condition] = None

    # -- bookkeeping ---------------------------------------------------------

    def used_bytes(self) -> int:
        return sum(e["size"] for e in self.entries.values())

    def committed(self) -> int:
        return self.used_bytes() + self.reserved

    def disk_bytes(self) -> int:
        """Bytes actually on disk in the folder (for tests and checks)."""
        total = 0
        for root, _dirs, files in os.walk(self.root):
            for name in files:
                try:
                    total += os.lstat(os.path.join(root, name)).st_size
                except OSError:
                    pass
        return total

    def work_root(self) -> str:
        return os.path.join(self.root, WORK_NAME)

    def new_work_dir(self) -> str:
        os.makedirs(self.work_root(), mode=0o700, exist_ok=True)
        path = os.path.join(self.work_root(), f"job-{os.urandom(8).hex()}")
        os.mkdir(path, 0o700)
        return path

    # -- index file ----------------------------------------------------------

    def _save(self) -> None:
        data = {"version": 1, "entries": self.entries}
        tmp = os.path.join(self.root, INDEX_NAME + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, os.path.join(self.root, INDEX_NAME))
        except OSError as e:
            logger.warning(f"VOD play cache: could not write the index: {e}")

    def reconcile(self) -> dict:
        """Load the index and make the folder agree with it: entries whose file is missing or has
        another size are dropped, files and work folders the index does not know are removed
        (names that are not ours are left alone). Blocking: run it in a thread at start."""
        stats = {"kept": 0, "dropped": 0, "strays": 0}
        loaded: dict = {}
        try:
            fd = os.open(os.path.join(self.root, INDEX_NAME), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            raw = data.get("entries") if isinstance(data, dict) else None
            loaded = raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            loaded = {}
        keep: dict = {}
        for key, e in loaded.items():
            try:
                ok = (isinstance(key, str) and _ENTRY_RE.match(key + ".mp4") and isinstance(e, dict)
                      and e.get("file") == key + ".mp4"
                      and all(isinstance(e.get(k), int) for k in ("size", "owner", "rsize", "rmtime"))
                      and isinstance(e.get("path"), str) and isinstance(e.get("ident"), str))
                if ok:
                    st = os.lstat(os.path.join(self.root, e["file"]))
                    ok = stat.S_ISREG(st.st_mode) and st.st_size == e["size"]
            except OSError:
                ok = False
            if ok:
                e["used"] = float(e.get("used") or 0)
                keep[key] = e
            else:
                stats["dropped"] += 1
        known = {e["file"] for e in keep.values()}
        try:
            names = os.listdir(self.root)
        except OSError:
            names = []
        for name in names:
            if name in (MARKER_NAME, INDEX_NAME) or name in known:
                continue
            full = os.path.join(self.root, name)
            if name == WORK_NAME:
                try:
                    inner = os.listdir(full)
                except OSError:
                    inner = []
                for sub in inner:
                    _remove_path(os.path.join(full, sub))
                    stats["strays"] += 1
            elif _ENTRY_RE.match(name) or name == INDEX_NAME + ".tmp":
                _remove_path(full)
                stats["strays"] += 1
            else:
                logger.warning(f"VOD play cache: leaving {name!r} alone, it is not a cache file")
        for e in keep.values():
            try:
                os.chmod(os.path.join(self.root, e["file"]), 0o600)
            except OSError:
                pass
        self.entries = keep
        stats["kept"] = len(keep)
        self._save()
        return stats

    # -- entries -------------------------------------------------------------

    def get(self, key: str) -> Optional[str]:
        """The cached file for *key* (and mark it used), or None. A file that went missing or changed
        size is dropped from the index."""
        e = self.entries.get(key)
        if not e:
            return None
        path = os.path.join(self.root, e["file"])
        try:
            st = os.lstat(path)
            ok = stat.S_ISREG(st.st_mode) and st.st_size == e["size"]
        except OSError:
            ok = False
        if not ok:
            self.entries.pop(key, None)
            self._save()
            return None
        e["used"] = time.time()
        return path

    def _drop(self, key: str) -> None:
        e = self.entries.pop(key, None)
        if e:
            _remove_path(os.path.join(self.root, e["file"]))

    def evict_to(self, cap: int) -> int:
        """Evict least recently used entries until entries plus reservations fit in *cap*. Returns the count."""
        n = 0
        for key in sorted(self.entries, key=lambda k: self.entries[k]["used"]):
            if self.committed() <= cap:
                break
            self._drop(key)
            n += 1
        if n:
            self._save()
            self._notify()
        return n

    def add(self, key: str, tmp_path: str, meta: dict, reserved: int) -> bool:
        """Move a finished MP4 into the cache as *key* and give back the job's reservation.
        The file must be a regular file of ours inside the folder. False when it cannot be added."""
        try:
            st = os.lstat(tmp_path)
            if not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
                return False
            dest = os.path.join(self.root, key + ".mp4")
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, dest)
        except OSError as e:
            logger.warning(f"VOD play cache: could not add an entry: {e}")
            return False
        finally:
            self.release(reserved)
        old = self.entries.pop(key, None)
        entry = dict(meta)
        entry.update({"file": key + ".mp4", "size": st.st_size, "used": time.time()})
        self.entries[key] = entry
        del old
        self._save()
        return True

    def purge(self, owner: Optional[int] = None, ident_not: Optional[str] = None,
              path: Optional[str] = None) -> int:
        """Remove every entry (of one owner; with *ident_not*, only those from another storage; with
        *path*, only that chunk). Returns the count."""
        n = 0
        for key in list(self.entries):
            e = self.entries[key]
            if owner is not None and e["owner"] != owner:
                continue
            if path is not None and e["path"] != path:
                continue
            if ident_not is not None and e["ident"] == ident_not:
                continue
            self._drop(key)
            n += 1
        if n:
            self._save()
            self._notify()
        return n

    def owners(self) -> dict:
        """owner -> set of storage idents present in the cache."""
        out: dict = {}
        for e in self.entries.values():
            out.setdefault(e["owner"], set()).add(e["ident"])
        return out

    # -- reservations --------------------------------------------------------

    def _condition(self) -> asyncio.Condition:
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    def _notify(self) -> None:
        cond = self._cond
        if cond is None:
            return

        async def wake():
            async with cond:
                cond.notify_all()
        try:
            asyncio.get_running_loop().create_task(wake())
        except RuntimeError:
            pass

    def release(self, n: int) -> None:
        self.reserved = max(0, self.reserved - int(n))
        self._notify()

    def try_reserve(self, n: int, cap: int) -> bool:
        """Reserve *n* bytes, evicting least recently used entries to make room. False when it does not fit now."""
        if n > cap:
            return False
        self.evict_to(cap - n)
        if self.committed() + n > cap:
            return False
        self.reserved += n
        return True

    async def reserve(self, n: int, cap: int, timeout: float) -> bool:
        """Like try_reserve, but waits (up to *timeout*) for running jobs to finish and free their share."""
        if n > cap:
            return False
        cond = self._condition()
        deadline = time.monotonic() + timeout
        async with cond:
            while True:
                if self.try_reserve(n, cap):
                    return True
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                try:
                    await asyncio.wait_for(cond.wait(), min(left, 5.0))
                except asyncio.TimeoutError:
                    pass
