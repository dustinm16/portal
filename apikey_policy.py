"""API key policy: the scope registry, address bindings and the default expiry.

One place lists every scope the code itself checks, with a description, so the
create route can refuse a scope nothing would ever honour and the key window
can offer a picker. Scopes an administrator makes up for a service
(``required_scopes`` on the service row) are data, not code; they are accepted
too when the create route passes them in as ``extra_known``.

Where the code checks a scope (grep ``has_scope`` and ``_FULL_USER_SCOPES`` in
server.py):

* ``*`` - passes every check.
* ``admin`` - the administrator routes (``has_scope("admin")``), and the
  built-in web terminal service.
* ``services:read`` and ``access:*`` - what a signed-in member who is not an
  administrator carries (``_FULL_USER_SCOPES``); together they make a
  credential "full" for ``has_full_user_scope``.

Pure functions, no database and no server import, so they are easy to test.
"""

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

DEFAULT_EXPIRY_DAYS = 90
MAX_EXPIRY_DAYS = 3650
STALE_DAYS = 90
MAX_CIDRS = 10
MAX_SCOPES = 20
MAX_INPUT_CHARS = 2000

# Scopes a member who is not an administrator gets, whatever he asks for.
LIMITED_SCOPES = "services:read,access:*"

SCOPE_REGISTRY: dict[str, str] = {
    "*": "Everything the account may do. Use only when a narrower scope will not do.",
    "admin": "Administrator routes (users, services, settings, security). Works only for an administrator's key.",
    "services:read": "See the service list and open the services the account may use.",
    "access:*": "Member access: the rest of what a signed-in member's browser session carries.",
}

_SCOPE_RE = re.compile(r"^[a-z0-9_*.\-]{1,64}(:[a-z0-9_*.\-]{1,64}){0,3}$")


class PolicyError(ValueError):
    """A request the create route must answer with 400."""


def _as_list(value, what: str) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        if len(value) > MAX_INPUT_CHARS:
            raise PolicyError(f"{what} is too long")
        return [p for p in re.split(r"[,\s]+", value) if p]
    if isinstance(value, (list, tuple)):
        if len(value) > 100:
            raise PolicyError(f"{what} has too many entries")
        return list(value)
    raise PolicyError(f"{what} must be a text or a list")


def _scope_covers(pattern: str, scope: str) -> bool:
    """True when the key scope `pattern` (which may hold "*" parts) matches `scope`,
    the same rule TokenPayload.has_scope applies."""
    if pattern == "*" or pattern == scope:
        return True
    pp, sp = pattern.split(":"), scope.split(":")
    return len(pp) == len(sp) and all(a == "*" or a == b for a, b in zip(pp, sp))


def normalise_scopes(value, extra_known: Iterable[str] = ()) -> list[str]:
    """The requested scopes as a clean list, or PolicyError for one nobody checks.

    A scope is known when it is in SCOPE_REGISTRY, is one a service requires
    (`extra_known`), or is a wildcard such as ``relay:*`` that covers one of those.
    """
    items = _as_list(value, "scopes")
    if not items:
        return ["*"]
    known = list(SCOPE_REGISTRY) + [s for s in extra_known if isinstance(s, str) and s]
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise PolicyError("Each scope must be text")
        s = item.strip().lower()
        if not _SCOPE_RE.match(s):
            raise PolicyError(f"Unknown scope: {s[:40]!r}")
        if not any(_scope_covers(s, k) for k in known):
            raise PolicyError(f"Unknown scope: {s[:40]!r}")
        if s not in out:
            out.append(s)
    if len(out) > MAX_SCOPES:
        raise PolicyError(f"At most {MAX_SCOPES} scopes")
    if "*" in out:
        return ["*"]
    return out


def normalise_cidrs(value) -> Optional[list[str]]:
    """Validated, normalised address bindings, or None for "not bound".

    Accepts a list or a comma/space separated text of addresses and networks,
    IPv4 and IPv6 (a bare address is a /32 or /128; host bits are cleared).
    At most MAX_CIDRS distinct entries. A /0 is refused: a key that works from
    anywhere is written ``any`` (alone) or left out. Raises PolicyError.
    """
    if value is None:
        return None
    items = _as_list(value, "allowed_cidrs")
    if not items:
        return None
    out: list[str] = []
    saw_any = False
    for item in items:
        if not isinstance(item, str):
            raise PolicyError("Each allowed address must be text")
        s = item.strip()
        if not s:
            raise PolicyError("An allowed address is empty")
        if s.lower() == "any":
            saw_any = True
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise PolicyError(f"Not an address or network: {s[:60]!r}")
        if net.version == 6 and net.network_address.ipv4_mapped is not None:
            raise PolicyError(f"Write the IPv4 form of {s[:60]!r}")
        if net.prefixlen == 0:
            raise PolicyError("A /0 network allows every address; write \"any\" if that is what you mean")
        text = str(net)
        if text not in out:
            out.append(text)
    if saw_any:
        if out:
            raise PolicyError("\"any\" cannot be combined with other addresses")
        return None
    if len(out) > MAX_CIDRS:
        raise PolicyError(f"At most {MAX_CIDRS} allowed addresses")
    return out


def cidrs_to_text(cidrs: Optional[list[str]]) -> Optional[str]:
    return ",".join(cidrs) if cidrs else None


def cidrs_from_text(text) -> list[str]:
    return [p for p in str(text).split(",") if p] if text else []


def client_in_cidrs(client_ip, cidrs: list[str]) -> bool:
    """True when `client_ip` lies in one of `cidrs`. A missing or unreadable
    address never matches (a bound key fails closed)."""
    if not cidrs:
        return True
    try:
        addr = ipaddress.ip_address(str(client_ip).strip())
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version == addr.version and addr in net:
            return True
    return False


def resolve_expiry(data: dict, now: Optional[datetime] = None) -> tuple[Optional[str], Optional[int]]:
    """(expires_at ISO text or None, days or None) from a create request.

    `expires_days` absent or null: DEFAULT_EXPIRY_DAYS. ``"never"`` or ``0``:
    no expiry. A whole number of days up to MAX_EXPIRY_DAYS: that long. Anything
    else is refused (an unreadable value used to mean "never"). The older
    `expires_in_days` spelling the key window sent is read when `expires_days`
    is absent.
    """
    now = now or datetime.now(timezone.utc)
    raw = data.get("expires_days")
    if raw is None:
        raw = data.get("expires_in_days")
    if raw is None:
        days: Optional[int] = DEFAULT_EXPIRY_DAYS
    elif isinstance(raw, str) and raw.strip().lower() == "never":
        days = None
    else:
        if isinstance(raw, bool):
            raise PolicyError("expires_days must be a number of days or \"never\"")
        try:
            days = int(str(raw).strip()) if isinstance(raw, str) else (raw if isinstance(raw, int) else None)
        except ValueError:
            days = None
        if days is None:
            raise PolicyError("expires_days must be a number of days or \"never\"")
        if days == 0:
            days = None
        elif days < 0 or days > MAX_EXPIRY_DAYS:
            raise PolicyError(f"expires_days must be between 1 and {MAX_EXPIRY_DAYS}, or \"never\"")
    if days is None:
        return None, None
    return (now + timedelta(days=days)).isoformat(), days


def parse_db_time(value) -> Optional[datetime]:
    """A stored timestamp (space or T separator, with or without a zone) as aware UTC."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_stale(key: dict, now: Optional[datetime] = None) -> bool:
    """A live key not used for STALE_DAYS (or never used and made that long ago)."""
    if key.get("revoked"):
        return False
    now = now or datetime.now(timezone.utc)
    exp = parse_db_time(key.get("expires_at"))
    if exp is not None and exp < now:
        return False
    seen = parse_db_time(key.get("last_used_at")) or parse_db_time(key.get("created_at"))
    if seen is None:
        return False
    return now - seen >= timedelta(days=STALE_DAYS)


def no_expiry_warning(scopes: list[str], expires_at) -> Optional[str]:
    if expires_at is None and "*" in scopes:
        return ("This key has full access and never expires. Give it an expiry or narrower "
                "scopes, and bind it to the addresses it is used from.")
    return None
