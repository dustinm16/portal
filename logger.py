"""Open Relay Portal - Logging Configuration.

Features:
- Structured JSON logging support
- Sensitive data filtering (passwords, tokens, keys)
- Rotating file handler with configurable size
- Runtime log level adjustment
- Security audit logging

All traffic uses HTTPS on port 443. Logging excludes sensitive data.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# Default log directory
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "portal.log"
AUDIT_FILE = LOG_DIR / "audit.log"

# Patterns to filter from logs (security)
SENSITIVE_PATTERNS = [
    (re.compile(r'(password["\s:=]+)[^\s,}\]"]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token["\s:=]+)[A-Za-z0-9_-]{20,}', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key["\s:=]+)portal_[A-Za-z0-9_-]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret["\s:=]+)[^\s,}\]"]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(-----BEGIN[^-]+-----)[^-]+(-----END[^-]+-----)', re.DOTALL), r'\1[REDACTED]\2'),
    (re.compile(r'rtmp_[A-Za-z0-9_-]{20,}'), '[RTMP_TOKEN_REDACTED]'),
    (re.compile(r'live_[A-Za-z0-9_-]{16,}'), '[STREAM_KEY_REDACTED]'),
    (re.compile(r'pub_[A-Za-z0-9_-]{16,}'), '[PUBLIC_KEY_REDACTED]'),
]

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


class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive data from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if LOG_SETTINGS.get("filter_sensitive", True):
            msg = str(record.msg)
            for pattern, replacement in SENSITIVE_PATTERNS:
                msg = pattern.sub(replacement, msg)
            record.msg = msg
            # Also filter args if present
            if record.args:
                args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        for pattern, replacement in SENSITIVE_PATTERNS:
                            arg = pattern.sub(replacement, arg)
                    args.append(arg)
                record.args = tuple(args)
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
            log_data["exception"] = self.formatException(record.exc_info)
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

    # Create formatter based on settings
    if LOG_SETTINGS.get("structured", False):
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Console handler
    if LOG_SETTINGS["console_enabled"]:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(getattr(logging, LOG_SETTINGS["level"]))
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
        file_handler.addFilter(sensitive_filter)
        root_logger.addHandler(file_handler)

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
