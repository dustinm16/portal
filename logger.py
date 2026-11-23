"""Open Relay Portal - Logging Configuration.

Features:
- Structured JSON logging support
- Sensitive data filtering (passwords, tokens, keys)
- Rotating file handler with configurable size
- Runtime log level adjustment
- Security audit logging

All traffic uses HTTPS on port 443. Logging excludes sensitive data.
"""

import contextvars
import json
import logging
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# Default log directory
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "portal.log"
AUDIT_FILE = LOG_DIR / "audit.log"

# Patterns to filter from logs (security). Compiled once at import time.
# Redaction must be idempotent: the filter runs once per handler on the same record.
SENSITIVE_PATTERNS = [
    (re.compile(r'(password["\s:=]+)[^\s,}\]"]+', re.IGNORECASE), r'\1[REDACTED]'),
    # token= / ticket= / session= (query strings, form bodies): redact the whole
    # value, including the dots of a JWT, whatever its length. session= is the
    # media server's per-viewer HLS session value, forwarded in segment URLs.
    (re.compile(r'((?:token|ticket|session)=)[^\s&"\'#<>]*', re.IGNORECASE), r'\1[REDACTED]'),
    # "token: xxx" / "token": "xxx" forms; JWT-aware character class.
    (re.compile(r'(token["\s:=]+)[A-Za-z0-9._~+/-]{20,}', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key["\s:=]+)portal_[A-Za-z0-9_-]+', re.IGNORECASE), r'\1[REDACTED]'),
    # Portal API keys anywhere (headers, URLs, messages)
    (re.compile(r'portal_[A-Za-z0-9]{32,}'), '[API_KEY_REDACTED]'),
    (re.compile(r'(secret["\s:=]+)[^\s,}\]"]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(-----BEGIN[^-]+-----)[^-]+(-----END[^-]+-----)', re.DOTALL), r'\1[REDACTED]\2'),
    (re.compile(r'rtmp_[A-Za-z0-9_-]{20,}'), '[RTMP_TOKEN_REDACTED]'),
    (re.compile(r'live_[A-Za-z0-9_-]{16,}'), '[STREAM_KEY_REDACTED]'),
    # Stream playback keys (pub_xxx) are secrets too: a private stream's
    # playback key is all that grants viewing access, so they must never be
    # readable in logs. (Older versions left them readable on purpose.)
    (re.compile(r'pub_[A-Za-z0-9_-]{16,}'), '[PLAYBACK_KEY_REDACTED]'),
    # Key segment of stream proxy URLs (/api/stream/<key>/...). Playback URLs
    # may carry the key without its pub_/live_ prefix, so redact the segment
    # itself; the MediaMTX hook endpoints (/api/stream/auth, /event) are not keys.
    (re.compile(r'(/api/stream/)(?!(?:auth|event)(?:[/?\s"]|$))[^/\s?"\']+'), r'\1[STREAM_KEY_REDACTED]'),
    # Incoming-webhook URLs carry their bearer token as the last path segment
    # (/api/webhooks/incoming/<token>); the token has no recognisable prefix.
    (re.compile(r'(/api/webhooks/incoming/)[^/\s?"\']+'), r'\1[REDACTED]'),
    # The calendar feed carries its read-only token as the last path segment (/api/streams/schedule/feed/<token>.ics);
    # the token is not prefixed by anything the other rules know, and proxies log the path.
    (re.compile(r'(/api/streams/schedule/feed/)[^/\s?"\']+'), r'\1[REDACTED]'),
]

# Cheap pre-check so ordinary log lines skip the full pattern list.
_QUICK_CHECK = re.compile(
    r'password|token|ticket|session=|api[_-]?key|secret|BEGIN|portal_|rtmp_|live_|pub_|/api/stream/|/api/webhooks/incoming/|/api/streams/schedule/feed/',
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Apply every SENSITIVE_PATTERNS rule to text."""
    if not text or not _QUICK_CHECK.search(text):
        return text
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# Log settings (can be modified at runtime)
LOG_SETTINGS = {
    "level": "INFO",
    "max_size_mb": 10,
    "backup_count": 5,
    "console_enabled": True,
    "file_enabled": True,
    "structured": False,  # JSON format
    "filter_sensitive": True,  # Redact sensitive data
}


# ---------------------------------------------------------------------------
# Request IDs
#
# Every request gets a short random ID (server.request_id_middleware). The ID
# is made here, from the secrets module; nothing a client sends is ever used
# for it. While a request is handled the ID sits in a ContextVar and
# RequestIdFilter copies it onto each log record, so a line written by any code
# the request reaches carries it. A line written outside a request has no ID
# and is formatted exactly as before.
# ---------------------------------------------------------------------------

REQUEST_ID_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no 0/o/1/l/i, easy to read out
REQUEST_ID_LENGTH = 8
class _RequestIdHolder:
    """The ID of one request. The ContextVar holds this object, not the bare string, so a background
    task or thread started by the request (it copies the context, and with it this object) stops
    tagging its lines once the request has ended: reset_request_id clears the holder."""
    __slots__ = ("id",)

    def __init__(self, request_id):
        self.id = request_id


_request_id_var = contextvars.ContextVar("portal_request_id", default=None)


def new_request_id() -> str:
    """A fresh 8 character request ID."""
    return "".join(secrets.choice(REQUEST_ID_ALPHABET) for _ in range(REQUEST_ID_LENGTH))


def set_request_id(request_id: Optional[str]):
    """Make request_id the current one; returns the handle for reset_request_id."""
    holder = _RequestIdHolder(request_id)
    return _request_id_var.set(holder), holder


def reset_request_id(handle) -> None:
    """End the request: its ID is cleared everywhere it was copied to, and the context is restored."""
    token, holder = handle
    holder.id = None
    _request_id_var.reset(token)


def current_request_id() -> Optional[str]:
    """The ID of the request being handled in this context, or None."""
    holder = _request_id_var.get()
    return holder.id if holder is not None else None


class RequestIdFilter(logging.Filter):
    """Put the current request ID on the record as record.request_id (only inside a request).

    The record is shared by every handler, so the filter only sets an attribute:
    it never edits the message (that would repeat the ID once per handler).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        rid = current_request_id()
        if rid and not hasattr(record, "request_id"):
            record.request_id = rid
        return True


class RequestIdFormatter(logging.Formatter):
    """The text log format; a line from inside a request reads
    ``<time> [LEVEL] <logger>: [req=abcd2345] <message>``, any other line is unchanged."""

    def formatMessage(self, record: logging.LogRecord) -> str:
        rid = getattr(record, "request_id", None)
        if not rid:
            return super().formatMessage(record)
        saved = record.message
        record.message = f"[req={rid}] {saved}"
        try:
            return super().formatMessage(record)
        finally:
            record.message = saved


_CLIENT_ID_HEADER = re.compile(r"((?:x-request-id|x-correlation-id|request-id)\s*:).*", re.IGNORECASE | re.DOTALL)


class BadRequestNoiseFilter(logging.Filter):
    """Collapse aiohttp's "Error handling request" tracebacks for unparseable
    HTTP into a single INFO line."""

    def filter(self, record: logging.LogRecord) -> bool:
        exc = record.exc_info[1] if record.exc_info else None
        if exc is not None and type(exc).__name__ in (
            "BadHttpMessage", "BadHttpMethod", "BadStatusLine", "InvalidHeader",
            "LineTooLong", "InvalidURLError", "ContentLengthError", "TransferEncodingError",
        ):
            reason = " ".join(str(getattr(exc, "message", exc)).split())
            # The excerpt of the bad bytes is attacker text. A request ID header a client
            # sent is never logged: from the header name on, the rest of the excerpt goes.
            reason = _CLIENT_ID_HEADER.sub(r"\1 [omitted]", reason)[:120]
            record.msg = f"{record.getMessage()}: malformed request ({reason})"
            record.args = None
            record.exc_info = None
            record.exc_text = None
            record.levelno = logging.INFO
            record.levelname = "INFO"
        return True


LOGGED_ONCE_ATTR = "_portal_logged_once"


class LoggedOnceFilter(logging.Filter):
    """Drop aiohttp's "Error handling request" line for an exception that the request ID middleware
    has already logged under the request's ID (it marks the exception after writing its own line)."""

    def filter(self, record: logging.LogRecord) -> bool:
        exc = record.exc_info[1] if record.exc_info else None
        return not (exc is not None and getattr(exc, LOGGED_ONCE_ATTR, False))


class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive data from log messages."""

    _exc_formatter = logging.Formatter()

    def filter(self, record: logging.LogRecord) -> bool:
        if LOG_SETTINGS.get("filter_sensitive", True):
            # Redact the fully formatted message, so a secret is caught whether
            # it sits in the format string or in any argument (positional,
            # mapping, or a non-string object such as a URL or exception).
            try:
                msg = record.getMessage()
            except Exception:
                msg = str(record.msg)
            record.msg = redact(msg)
            record.args = None
            # Exception text is rendered later by the formatter; render and
            # redact it now (the formatter reuses record.exc_text).
            if record.exc_info:
                if not record.exc_text:
                    try:
                        record.exc_text = self._exc_formatter.formatException(record.exc_info)
                    except Exception:
                        record.exc_text = None
                if record.exc_text:
                    record.exc_text = redact(record.exc_text)
            if record.stack_info:
                record.stack_info = redact(record.stack_info)
        return True


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = record.exc_text or self.formatException(record.exc_info)
        # Add extra fields if present
        for key in ['user_id', 'client_ip', 'request_id', 'action', 'resource']:
            if hasattr(record, key):
                log_data[key] = getattr(record, key)
        return json.dumps(log_data)


def setup_logging(
    level: str = None,
    log_dir: Path = None,
    max_size_mb: int = None,
    backup_count: int = None,
    console_enabled: bool = None,
    file_enabled: bool = None,
    structured: bool = None,
) -> None:
    """Configure logging with rotation."""
    global LOG_SETTINGS, LOG_DIR, LOG_FILE, AUDIT_FILE

    # Update settings
    if level:
        LOG_SETTINGS["level"] = level.upper()
    if max_size_mb is not None:
        LOG_SETTINGS["max_size_mb"] = max_size_mb
    if backup_count is not None:
        LOG_SETTINGS["backup_count"] = backup_count
    if console_enabled is not None:
        LOG_SETTINGS["console_enabled"] = console_enabled
    if file_enabled is not None:
        LOG_SETTINGS["file_enabled"] = file_enabled
    if structured is not None:
        LOG_SETTINGS["structured"] = structured
    if log_dir:
        LOG_DIR = Path(log_dir)
        LOG_FILE = LOG_DIR / "portal.log"
        AUDIT_FILE = LOG_DIR / "audit.log"

    # Create log directory
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, LOG_SETTINGS["level"]))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Sensitive data filter — must be on handlers, not the root logger.
    # Filters on a logger only apply to records logged directly on that logger,
    # NOT to records propagated from child loggers (e.g. "portal", "aiohttp.access").
    # Adding the filter to each handler ensures ALL records are sanitized.
    sensitive_filter = SensitiveDataFilter()
    request_id_filter = RequestIdFilter()

    # Create formatter based on settings
    if LOG_SETTINGS.get("structured", False):
        formatter = StructuredFormatter()
    else:
        formatter = RequestIdFormatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Console handler
    if LOG_SETTINGS["console_enabled"]:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(getattr(logging, LOG_SETTINGS["level"]))
        console_handler.addFilter(request_id_filter)
        console_handler.addFilter(sensitive_filter)
        root_logger.addHandler(console_handler)

    # File handler with rotation
    if LOG_SETTINGS["file_enabled"]:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_SETTINGS["max_size_mb"] * 1024 * 1024,
            backupCount=LOG_SETTINGS["backup_count"],
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(getattr(logging, LOG_SETTINGS["level"]))
        file_handler.addFilter(request_id_filter)
        file_handler.addFilter(sensitive_filter)
        root_logger.addHandler(file_handler)

    # Malformed requests (port scanners, TLS/HTTP2 probes) are routine on a
    # public host: keep one line, drop the traceback.
    server_logger = logging.getLogger("aiohttp.server")
    if not any(isinstance(f, BadRequestNoiseFilter) for f in server_logger.filters):
        server_logger.addFilter(BadRequestNoiseFilter())
    if not any(isinstance(f, LoggedOnceFilter) for f in server_logger.filters):
        server_logger.addFilter(LoggedOnceFilter())

    # Set levels for noisy loggers
    logging.getLogger("aiohttp.access").setLevel(logging.INFO)
    logging.getLogger("websockets").setLevel(logging.WARNING)


def get_log_level() -> str:
    """Get current log level."""
    return LOG_SETTINGS["level"]


def set_log_level(level: str) -> None:
    """Set log level at runtime."""
    level = level.upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ValueError(f"Invalid log level: {level}")

    LOG_SETTINGS["level"] = level
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level))

    for handler in root_logger.handlers:
        handler.setLevel(getattr(logging, level))


def get_log_files() -> list[dict]:
    """Get list of log files with metadata."""
    files = []
    if LOG_DIR.exists():
        for f in sorted(LOG_DIR.glob("portal.log*"), reverse=True):
            stat = f.stat()
            files.append({
                "name": f.name,
                "path": str(f),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return files


def read_log_file(filename: str = "portal.log", lines: int = 500, offset: int = 0) -> dict:
    """Read log file contents (tail)."""
    log_path = LOG_DIR / filename

    # Security check - only allow reading from log directory
    if not log_path.resolve().parent == LOG_DIR.resolve():
        return {"error": "Invalid log file path"}

    if not log_path.exists():
        return {"error": "Log file not found", "lines": [], "total": 0}

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        total = len(all_lines)

        # Get last N lines with offset
        if offset > 0:
            end = max(0, total - offset)
            start = max(0, end - lines)
            selected = all_lines[start:end]
        else:
            selected = all_lines[-lines:] if lines < total else all_lines

        return {
            "lines": [line.rstrip() for line in selected],
            "total": total,
            "file": filename,
        }
    except Exception as e:
        return {"error": str(e), "lines": [], "total": 0}


def clear_old_logs() -> int:
    """Delete old rotated log files, keep only the main log."""
    count = 0
    if LOG_DIR.exists():
        for f in LOG_DIR.glob("portal.log.*"):
            try:
                f.unlink()
                count += 1
            except OSError:
                pass
    return count


def get_log_settings() -> dict:
    """Get current log settings."""
    return {
        "level": LOG_SETTINGS["level"],
        "max_size_mb": LOG_SETTINGS["max_size_mb"],
        "backup_count": LOG_SETTINGS["backup_count"],
        "console_enabled": LOG_SETTINGS["console_enabled"],
        "file_enabled": LOG_SETTINGS["file_enabled"],
        "log_dir": str(LOG_DIR),
        "log_file": str(LOG_FILE),
    }


def update_log_settings(settings: dict) -> dict:
    """Update log settings."""
    if "level" in settings:
        set_log_level(settings["level"])

    if "max_size_mb" in settings:
        LOG_SETTINGS["max_size_mb"] = int(settings["max_size_mb"])

    if "backup_count" in settings:
        LOG_SETTINGS["backup_count"] = int(settings["backup_count"])

    # Reconfigure handlers if size/count changed
    setup_logging()

    return get_log_settings()
