"""SSH host-key pinning (trust on first use) for every place the portal dials SSH.

A connection stores the SHA256 fingerprint of its server's host key in its
encrypted config (`host_key_fingerprint`). The key is checked during the SSH
key exchange, before any password or private key is offered: the connect fails
with HostKeyRefused instead. Nothing here writes a pin; accepting a key is a
separate, authenticated HTTP action (see the accept routes in server.py).

Config keys (all inside the connection's / service's / VOD storage's config):

    host_key_fingerprint   "SHA256:<43 base64 chars>", set only by an accept route
    host_key_ignore        true = explicit opt-out, the key is not checked

The older `known_hosts` setting of the ssh plugin is not read any more.

Host certificates are not trusted: the client asks the server for its plain
public key (no certificate algorithms), so a server that has a host certificate
is pinned by its underlying key like any other. The pin is the fingerprint of
the key the server presented; a server that begins to offer a different key
type can show as "changed".
"""

import hmac
import re
import time
from typing import Optional

import asyncssh

from host_check import try_each_address

FINGERPRINT_KEY = "host_key_fingerprint"
IGNORE_KEY = "host_key_ignore"
# Last key a VOD upload refused (the VOD storage has no interactive prompt).
REFUSED_KEY = "host_key_refused"

STATE_UNPINNED = "unpinned"
STATE_CHANGED = "changed"

_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def valid_fingerprint(value) -> bool:
    return isinstance(value, str) and bool(_FP_RE.match(value))


def normalize_fingerprint(value) -> Optional[str]:
    """Return the canonical fingerprint text, or None when it is not one."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("sha256:"):
        text = "SHA256:" + text[len("sha256:"):]
    # OpenSSH prints the hash without '=' padding; accept one that kept it.
    text = text.rstrip("=")
    return text if _FP_RE.match(text) else None


def fingerprint_of(key) -> str:
    """SHA256 fingerprint of an asyncssh public key, as ssh-keygen prints it."""
    return key.get_fingerprint("sha256")


class HostKeyRefused(Exception):
    """The server's host key was not accepted; no credential was sent."""

    def __init__(self, state: str, fingerprint: str, expected: Optional[str] = None,
                 algorithm: Optional[str] = None):
        super().__init__(f"host key {state}")
        self.state = state
        self.fingerprint = fingerprint
        self.expected = expected
        self.algorithm = algorithm      # key type the server presented, e.g. ssh-ed25519


def policy_for(config) -> tuple:
    """(pinned fingerprint or None, ignore flag) for a connection config."""
    if not isinstance(config, dict):
        return None, False
    pinned = normalize_fingerprint(config.get(FINGERPRINT_KEY))
    return pinned, config.get(IGNORE_KEY) is True


def _apply_pin(existing: dict, out: dict, incoming: dict, *, target_changed: bool,
               trusted_incoming: bool) -> dict:
    out.pop(REFUSED_KEY, None)
    pin = normalize_fingerprint(existing.get(FINGERPRINT_KEY))
    if target_changed:
        pin = None
    if trusted_incoming and FINGERPRINT_KEY in incoming:
        raw = incoming.get(FINGERPRINT_KEY)
        if not raw:
            pin = None                      # an explicit empty value clears the pin
        elif normalize_fingerprint(raw):
            pin = normalize_fingerprint(raw)
        # anything else (a placeholder, a typo) leaves the stored pin as it is
    if pin:
        out[FINGERPRINT_KEY] = pin
    else:
        out.pop(FINGERPRINT_KEY, None)
    return out


def guard_config(existing, incoming, *, target_changed: bool, trusted_incoming: bool = False) -> dict:
    """Merge an edited config over the stored one without letting the editor
    set or keep a host-key pin it did not earn.

    The pin always comes from `existing`, except that it is dropped when the
    host or port changed. With trusted_incoming (an admin pre-filling a service)
    a valid fingerprint in `incoming` replaces it, and an empty string clears it;
    an invalid value is ignored.
    """
    existing = existing if isinstance(existing, dict) else {}
    incoming = incoming if isinstance(incoming, dict) else {}
    return _apply_pin(existing, {**existing, **incoming}, incoming,
                      target_changed=target_changed, trusted_incoming=trusted_incoming)


def guard_replacement(existing, new_config, *, target_changed: bool, trusted_incoming: bool = False) -> dict:
    """Like guard_config for an editor that replaces the whole config (admin
    service edit): everything in `new_config` is kept, only the pin is guarded."""
    existing = existing if isinstance(existing, dict) else {}
    new_config = new_config if isinstance(new_config, dict) else {}
    return _apply_pin(existing, dict(new_config), new_config,
                      target_changed=target_changed, trusted_incoming=trusted_incoming)


def strip_new_pin(config) -> dict:
    """A config being created: it cannot arrive with a pin or a refused key."""
    out = dict(config) if isinstance(config, dict) else {}
    out.pop(FINGERPRINT_KEY, None)
    out.pop(REFUSED_KEY, None)
    return out


# Options a caller may pass to connect_verified / locked_client_options. The
# portal runs as a privileged user, so asyncssh must never fall back to that
# user's own SSH identity: with `client_keys` unset it loads ~/.ssh/id_* and
# with `agent_path` unset it talks to $SSH_AUTH_SOCK; `config` unset reads
# ~/.ssh/config (ProxyCommand, ForwardAgent, IdentityFile ...). Only what the
# connection itself stores (password, private key) may ever be offered.
CALLER_OPTIONS = frozenset({
    "host", "port", "username", "password", "client_keys", "connect_timeout",
})

LOCKED_OPTIONS = {
    "config": [],                   # no ~/.ssh/config, no system config
    "agent_path": None,             # no ssh-agent (not even $SSH_AUTH_SOCK)
    "agent_identities": None,
    "agent_forwarding": False,      # never hand an agent to the remote host
    "pkcs11_provider": None,
    "gss_host": None,               # no GSSAPI key exchange / authentication
    "gss_kex": False,
    "gss_auth": False,
    "gss_delegate_creds": False,
    "host_based_auth": False,
    "client_host_keysign": False,
    "client_host_keys": None,
    "x509_trusted_certs": None,     # no ~/.ssh/ca-bundle.crt
    "x509_trusted_cert_paths": None,
    "x11_forwarding": False,
}


def locked_client_options(connect_opts: dict) -> dict:
    """The only way the portal builds asyncssh client options.

    Keeps the stored credential the caller passed (password and/or client_keys)
    and pins everything else that could pull in the process user's identity.
    `client_keys` is None, never an empty list, when there is no stored key
    (an empty list makes asyncssh load the default keys). An option outside
    CALLER_OPTIONS is a bug in the caller and raises ValueError.
    """
    extra = set(connect_opts) - CALLER_OPTIONS
    if extra:
        raise ValueError("unsupported SSH connect option: " + ", ".join(sorted(extra)))
    out = dict(connect_opts)
    out["client_keys"] = list(out["client_keys"]) if out.get("client_keys") else None
    out.update(LOCKED_OPTIONS)
    return out


class HostKeyAcceptToken:
    """Signed proof that the portal itself showed a user this host key.

    The accept routes take the host, port and fingerprint the user saw plus
    this token, so a stale dialog, a fingerprint typed in by hand or a request
    for a different connection cannot pin a key. No state is kept: the token
    is an HMAC over what was shown, who it was shown to, and an expiry.
    """

    TTL = 1800

    @staticmethod
    def _mac(secret: str, scope, ident, user_id, host, port, fingerprint, expires: int) -> str:
        key = hmac.new(secret.encode(), b"host-key-accept-v1", "sha256").digest()
        msg = "\x1f".join(str(x) for x in (scope, ident, user_id, host, port, fingerprint, expires))
        return hmac.new(key, msg.encode(), "sha256").hexdigest()

    @classmethod
    def issue(cls, secret: str, scope: str, ident, user_id, host, port, fingerprint: str,
              now: Optional[float] = None) -> str:
        expires = int((time.time() if now is None else now) + cls.TTL)
        return f"{expires}.{cls._mac(secret, scope, ident, user_id, host, port, fingerprint, expires)}"

    @classmethod
    def check(cls, secret: str, token, scope: str, ident, user_id, host, port, fingerprint: str,
              now: Optional[float] = None) -> bool:
        if not isinstance(token, str) or "." not in token or not secret:
            return False
        exp_text, _, mac = token.partition(".")
        if not exp_text.isdigit():
            return False
        expires = int(exp_text)
        if expires < (time.time() if now is None else now):
            return False
        good = cls._mac(secret, scope, ident, user_id, host, port, fingerprint, expires)
        return hmac.compare_digest(mac.encode(), good.encode())


def _no_known_hosts(host, addr, port):
    # Trust nothing from any file: every key goes to validate_host_public_key.
    # (A falsy known_hosts would make asyncssh read the user's known_hosts.)
    return ([], [], [])


class _Verifier:
    def __init__(self, pinned: Optional[str], trust_unpinned: bool):
        self.pinned = pinned
        self.trust_unpinned = trust_unpinned
        self.seen: Optional[str] = None
        self.seen_algorithm: Optional[str] = None

    def reset(self) -> None:
        """Forget the key seen so far (called before each address attempt)."""
        self.seen = None
        self.seen_algorithm = None

    def check(self, key) -> bool:
        fp = fingerprint_of(key)
        self.seen = fp
        self.seen_algorithm = key.algorithm.decode() if isinstance(key.algorithm, bytes) else str(key.algorithm)
        if self.pinned:
            return hmac.compare_digest(fp.encode(), self.pinned.encode())
        return self.trust_unpinned


class _PinClient(asyncssh.SSHClient):
    def __init__(self, verifier: _Verifier):
        self._verifier = verifier

    def validate_host_public_key(self, host, addr, port, key):
        return self._verifier.check(key)


async def connect_verified(addrs, connect_opts: dict, *, pinned: Optional[str], ignore: bool = False,
                           trust_unpinned: bool = False, timeout: Optional[float] = None):
    """Dial the checked addresses and verify the host key before authenticating.

    Returns (connection, fingerprint the server presented). With `ignore` the
    key is not checked (fingerprint is then None). With a pin, only that key is
    accepted. Without a pin the connect is refused unless `trust_unpinned`
    (the caller records the returned fingerprint). Raises HostKeyRefused
    when the key was not accepted; credentials are never sent in that case.
    """
    base = locked_client_options(connect_opts)

    if ignore:
        conn = await try_each_address(
            addrs,
            lambda a: asyncssh.connect(**{**base, "host": a, "known_hosts": None}),
            timeout)
        return conn, None

    verifier = _Verifier(pinned, trust_unpinned)
    # With no trusted CA, a server that offers an OpenSSH host certificate would
    # fail the certificate check before the key reaches the verifier, leaving
    # nothing to show the owner. Ask for plain keys only.
    plain_algs = [a.decode() for a in asyncssh.public_key.get_default_public_key_algs()]

    def attempt(addr):
        # Each address is a fresh handshake: a key seen by an earlier attempt
        # must not count as this one having run the validator.
        verifier.reset()
        return asyncssh.connect(
            **{**base, "host": addr, "known_hosts": _no_known_hosts,
               "server_host_key_algs": plain_algs,
               "client_factory": lambda: _PinClient(verifier)})

    try:
        conn = await try_each_address(addrs, attempt, timeout)
    except asyncssh.HostKeyNotVerifiable:
        if verifier.seen:
            raise HostKeyRefused(
                STATE_CHANGED if pinned else STATE_UNPINNED, verifier.seen, pinned,
                verifier.seen_algorithm) from None
        raise
    if verifier.seen is None:
        # The key exchange completed without the validator being called (a
        # GSS key exchange does that). Nothing was checked, so do not use it.
        conn.close()
        raise asyncssh.HostKeyNotVerifiable("The server's host key was not presented for verification")
    return conn, verifier.seen


def refusal_payload(refused: HostKeyRefused, *, can_accept: bool) -> dict:
    """The body shown to the user for a refused key (WebSocket message and
    HTTP error body). `can_accept` is computed by the server from the
    caller's identity; the client only displays it."""
    if refused.state == STATE_CHANGED:
        if can_accept:
            text = ("Host key changed. The server now presents a different key than the one "
                    "you accepted. This can mean it was reinstalled, or that the connection is "
                    "being intercepted. Check the new fingerprint with the server's "
                    "administrator before accepting it.")
        else:
            text = ("Host key changed. The connection was refused. Ask the owner "
                    "of this connection to review the new key.")
    else:
        if can_accept:
            text = ("This host's key has not been trusted yet. Compare the fingerprint with the "
                    "server's, then accept it to connect.")
        else:
            text = ("This host's key has not been confirmed by the owner of this connection. "
                    "Ask the owner to connect once and accept it.")
    return {
        "type": "host_key",
        "state": refused.state,
        "fingerprint": refused.fingerprint,
        "expected": refused.expected,
        "algorithm": refused.algorithm,
        "can_accept": bool(can_accept),
        "message": text,
    }
