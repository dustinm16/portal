"""Safety check for the terminal recordings folder.

Pure filesystem helpers with no dependency on the server module. The portal
changes the mode of the files in the recordings folder and removes recording
files that no database row refers to, so the folder has to be one that holds
nothing but recordings. A folder that fails the check is never changed or
swept, and recording stays off until the portal is restarted with a good
setting.
"""

import logging
import os
import stat
from pathlib import Path
from typing import Optional

import vod_staging

logger = logging.getLogger("portal")

RECORDING_SUFFIX = ".cast"
PROJECT_ROOT = os.path.realpath(str(Path(__file__).parent))

# Folders of the project that are served, hold backups or hold staged uploads.
_PROTECTED_SUBDIRS = ("static", "backups", os.path.join("data", "vod_tmp"))

# Folders already refused during this run: path -> reason. Logged once each.
_refused: dict = {}


def _inside(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent.rstrip(os.sep) + os.sep)


def refusal_reason(path: str, project_root: Optional[str] = None) -> Optional[str]:
    """Why *path* must not be the recordings folder, or None when it is fine.

    Refused: the filesystem root, a mount point, a shared temp folder, anything
    below /tmp or /var/tmp (except the portal's own default folder inside the
    project), a home directory, the project folder, static/, backups/ and
    data/vod_tmp (or anything below those), and an existing folder that holds
    anything besides *.cast files. An empty or missing folder is fine. No marker
    file is needed.
    """
    root = os.path.realpath(project_root or PROJECT_ROOT)
    real = os.path.realpath(path)
    own_default = real == os.path.join(root, "recordings")
    reason = vod_staging.dangerous_reason(real, root, allow_temp=own_default)
    if reason:
        return reason
    for sub in _PROTECTED_SUBDIRS:
        protected = os.path.join(root, sub)
        if _inside(real, os.path.realpath(protected)):
            return f"it is the project's {sub} folder or inside it"
    try:
        st = os.lstat(real)
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"it cannot be read: {e.strerror or e}"
    if not stat.S_ISDIR(st.st_mode):
        return "it is not a directory"
    try:
        with os.scandir(real) as entries:
            for entry in entries:
                if entry.name.endswith(RECORDING_SUFFIX) and not entry.is_dir(follow_symlinks=False):
                    continue
                return f"it holds {entry.name!r}, which is not a recording ({RECORDING_SUFFIX} file)"
    except OSError as e:
        return f"it cannot be read: {e.strerror or e}"
    return None


def check(path: str, project_root: Optional[str] = None) -> Optional[str]:
    """Return the refusal reason for *path*, or None when it may be used.

    A refusal is remembered for the rest of the run (and logged once), so a
    folder that was refused at start stays refused even if its content changes.
    """
    key = os.path.abspath(path)
    if key in _refused:
        return _refused[key]
    reason = refusal_reason(path, project_root)
    if reason:
        _refused[key] = reason
        logger.error(
            f"RECORDINGS_DIR {path} refused: {reason}. It was left untouched (not changed, not swept); "
            f"terminal recording is off until this is fixed and the portal is restarted"
        )
    return reason


def reset() -> None:
    """Forget remembered refusals (for tests)."""
    _refused.clear()
