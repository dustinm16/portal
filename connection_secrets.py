"""Stored secrets of user connections: which config keys hold one, how an answer hides it, and when a
changed target takes it away.

Two rules, kept in one place so every route that returns or edits a connection uses the same list:

- Write-only. Every answer that returns a connection (list, detail, connect) replaces each stored secret by a
  `has_<key>: true` flag; the value is never returned to any credential, whatever its scope. Only an edit
  that sends a new value changes it.
- A stored secret does not follow a moved target. When anything that decides where the portal dials changes
  (the row's host or port, the origin of a URL key, a TLS port, which plugin handles the type), every stored
  secret of the connection is removed unless the same request sends it again.

SECRET_KEYS and DIAL_KEYS are plain sets on purpose (not derived from the plugins at run time): a plugin field
that holds a credential or an address must be added here, and tests/test_connection_secrets.py walks every
plugin's config_schema so a new field that looks like either fails until it is listed (or named as harmless).
"""

import json
from typing import Optional
from urllib.parse import urlsplit

# Config keys that hold a secret the portal sends to the target (or uses to reach it). The first five were
# redacted before 1.24.1; the rest were returned in clear.
SECRET_KEYS = frozenset({
    "password", "private_key", "private_key_path", "auth_header", "psk",
    "api_token",            # proxmox
    "extra_headers",        # http: header values are credentials (an API key, a cookie)
    "personal_token", "client_secret", "webhook_secret",     # github
    "pre_shared_key",       # vpn_tunnel
})

# Keys that decide where the portal dials, besides the row's own host and port.
URL_KEYS = ("target_url", "api_url", "webrtc_url", "hls_url")      # compared by origin: scheme, host, port
ADDRESS_KEYS = ("host", "port", "tls_port", "tls", "allowed_ports")  # compared by value
DIAL_KEYS = frozenset(URL_KEYS) | frozenset(ADDRESS_KEYS)


def flag(key: str) -> str:
    return f"has_{key}"


def redact(config: dict, *, ssh_type: bool = False) -> dict:
    """`config` with each stored secret replaced by a has_<key> flag (nothing when it is empty).
    An SSH or SFTP connection's password is the stored password: one flag, has_stored_password."""
    out = {}
    for key, value in (config or {}).items():
        if key in SECRET_KEYS:
            if value:
                out["has_stored_password" if (ssh_type and key == "password") else flag(key)] = True
        else:
            out[key] = value
    return out


def strip_flags(config: dict) -> dict:
    """`config` without the has_<secret key> flags a client may have sent back from an earlier read."""
    return {k: v for k, v in config.items() if not (k.startswith("has_") and k[4:] in SECRET_KEYS)}


def _sent(value) -> bool:
    """Whether an incoming value counts as sending the secret again."""
    if isinstance(value, dict):
        return bool(value)
    return isinstance(value, str) and bool(value)


def _origin(url):
    """(scheme, host, port) of an http(s)/ws(s) URL with the default port filled in; the raw text when it
    cannot be parsed (a changed unparseable value is still a change)."""
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port or {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scheme)
    except ValueError:
        return ("raw", url.strip())
    return (scheme, host, port)


def _norm(value):
    if isinstance(value, (list, tuple)):
        return tuple(sorted(str(v) for v in value))
    if value is None or value == "" or value is False:
        return None
    return str(value).strip().lower()


def dial_changed(old_host, old_port, new_host, new_port, old_config: dict, new_config: dict) -> bool:
    """Whether anything that decides where the portal dials differs between the stored connection and what
    it would become. A path or a query of a URL is not part of it (the same host answers)."""
    if _norm(old_host) != _norm(new_host) or _norm(old_port) != _norm(new_port):
        return True
    old_config, new_config = old_config or {}, new_config or {}
    for key in URL_KEYS:
        if _origin(old_config.get(key)) != _origin(new_config.get(key)):
            return True
    for key in ADDRESS_KEYS:
        if _norm(old_config.get(key)) != _norm(new_config.get(key)):
            return True
    return False


def clear_on_move(*, moved: bool, existing: dict, incoming: dict, merged: dict, skip=()) -> tuple:
    """(config, cleared): `merged` without each stored secret the request did not send again, when `moved`.

    `existing` is the stored config, `incoming` what the request carried, `merged` the config the update
    would store. `cleared` lists the keys that held a value and were removed (sorted). `skip` names keys
    another rule owns (the SSH stored password). Nothing is touched when the target did not move."""
    if not moved:
        return merged, []
    out = dict(merged)
    cleared = []
    for key in sorted(SECRET_KEYS):
        if key in skip or key not in out:
            continue
        if _sent(incoming.get(key)):
            continue
        if _sent(out.get(key)) or _sent(existing.get(key)):
            cleared.append(key)
        del out[key]
    return out, cleared


def parse_config(config) -> dict:
    """A stored or incoming config as a dict (a JSON string, a dict, or nothing)."""
    if isinstance(config, str):
        try:
            config = json.loads(config) if config else {}
        except json.JSONDecodeError:
            return {}
    return config if isinstance(config, dict) else {}
