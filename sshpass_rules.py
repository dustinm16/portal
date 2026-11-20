"""Stored SSH password of a shared connection: the rules in one place.

The password lives in the connection's encrypted config under `password`, next to
`credential_mode`: "prompt" (the default; the terminal asks every time) or "stored"
(the terminal and the SFTP browser use the stored password and ask nothing).

Rules enforced here and by the callers in server.py, plugins/ssh.py and sftp_browser.py:

- Write-only. API responses carry `has_stored_password` and never the value
  (server.redact_connection_config). Only the owner's edit route can set, change
  or clear it; a grantee has no edit route.
- Setting `credential_mode` to "prompt" clears the stored password. So does an
  explicit empty `password`. An absent `password` keeps the stored one.
- A changed host, port, username or connection type clears it unless a new one comes in the
  same request. A row that moves to a type outside ssh/sftp keeps no stored password and no
  mode (apply_leaving); a password sent with that request is kept as the new type's own.
- A key authentication connection holds no stored password.
- In "stored" mode the host key must be pinned and verified: a connection that
  opts out of the host-key check cannot use a stored password (checked when it
  is saved and again when it is used).
"""

from typing import Optional

MODE_PROMPT = "prompt"
MODE_STORED = "stored"
MODES = (MODE_PROMPT, MODE_STORED)

# Connection types whose config this applies to (the SFTP browser's types).
TYPES = frozenset({"ssh", "sftp"})

MAX_PASSWORD_LEN = 1024


def stored_mode(config) -> bool:
    """True when the connection is set to use its stored password."""
    return isinstance(config, dict) and config.get("credential_mode") == MODE_STORED


def has_stored_password(config) -> bool:
    return isinstance(config, dict) and isinstance(config.get("password"), str) and bool(config["password"])


def terminal_password(config) -> Optional[str]:
    """The password the terminal may send without asking, or None (it asks).

    Only "stored" mode skips the prompt, so a connection without a mode behaves as
    before: it always prompts."""
    if stored_mode(config) and has_stored_password(config):
        return config["password"]
    return None


def sftp_password(config) -> Optional[str]:
    """The password the SFTP browser may send, or None.

    "prompt" never uses it (the browser has no prompt, so it reports that no credential
    is stored). A connection without a mode keeps the earlier behaviour: a stored
    password is used."""
    if isinstance(config, dict) and config.get("credential_mode") == MODE_PROMPT:
        return None
    return config["password"] if has_stored_password(config) else None


def check_incoming(config) -> Optional[str]:
    """An error text for a malformed credential field in an incoming config, else None."""
    if not isinstance(config, dict):
        return None
    if "credential_mode" in config and config["credential_mode"] not in MODES:
        return "Invalid credential mode"
    if "password" in config:
        pw = config["password"]
        if pw is not None and not isinstance(pw, str):
            return "Invalid password"
        if isinstance(pw, str) and (len(pw) > MAX_PASSWORD_LEN or "\x00" in pw):
            return "Invalid password"
    return None


def apply_rules(existing: dict, incoming: dict, merged: dict, *, identity_changed: bool) -> tuple:
    """Settle the password and the mode of a connection config being saved.

    `existing` is what is stored now ({} on create), `incoming` what the request sent,
    `merged` the config about to be stored (existing overlaid with incoming). Returns
    (config, cleared, error): `cleared` is True when a stored password was removed
    that the request did not ask to remove (host, port or username changed, or
    key authentication); `error` is a text for a 400 or None.
    """
    existing = existing if isinstance(existing, dict) else {}
    incoming = incoming if isinstance(incoming, dict) else {}
    out = dict(merged)
    had = has_stored_password(existing)

    supplied = isinstance(incoming.get("password"), str) and bool(incoming["password"])
    mode_in = incoming.get("credential_mode")

    pw = incoming["password"] if "password" in incoming else existing.get("password", "")
    pw = pw if isinstance(pw, str) else ""
    cleared = False

    if mode_in == MODE_PROMPT:
        pw = ""                                   # asking each time: nothing is kept
    elif identity_changed and not supplied:
        cleared = had
        pw = ""
    if out.get("auth_method") == "key" and not supplied:
        cleared = cleared or (had and bool(pw))
        pw = ""
    elif out.get("auth_method") == "key":
        return out, False, "A stored password is for password authentication"

    if pw:
        out["password"] = pw
    else:
        out.pop("password", None)

    if mode_in == MODE_PROMPT:
        mode = MODE_PROMPT
    elif pw and (supplied or mode_in == MODE_STORED):
        mode = MODE_STORED
    elif pw:
        mode = existing.get("credential_mode")           # unchanged: keeps a mode-less row mode-less
    elif mode_in == MODE_STORED and not cleared:
        return out, False, "Enter the password to store, or choose Prompt each time"
    elif mode_in or cleared or "credential_mode" in existing:
        mode = MODE_PROMPT
    else:
        mode = None
    if mode is None:
        out.pop("credential_mode", None)
    else:
        out["credential_mode"] = mode

    if mode == MODE_STORED and out.get("host_key_ignore") is True:
        return out, False, ("A stored password needs a verified host key: turn off "
                            "'Do not verify host key' or choose Prompt each time")
    return out, cleared, None


def apply_leaving(existing: dict, incoming: dict, merged: dict) -> tuple:
    """Settle the config of a row that moves from ssh/sftp to another type.

    The stored SSH password is not carried over: other plugins would send it to the
    client or to the (possibly new) host. Only a password in the same request stays,
    as the new type's own. `credential_mode` means nothing outside ssh/sftp and goes.
    Returns (config, cleared); `cleared` is True when a stored password was removed.
    """
    incoming = incoming if isinstance(incoming, dict) else {}
    out = dict(merged)
    supplied = isinstance(incoming.get("password"), str) and bool(incoming["password"])
    cleared = False
    if not supplied:
        cleared = has_stored_password(existing)
        out.pop("password", None)
    out.pop("credential_mode", None)
    return out, cleared
