"""Plain-assert tests for hostkeys (SSH host-key pinning), against a local
asyncssh server on 127.0.0.1 (no outbound network, no portal server).

Run:  venv/bin/python tests/test_hostkeys.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import asyncssh  # noqa: E402

import hostkeys  # noqa: E402
from hostkeys import HostKeyRefused, connect_verified  # noqa: E402

PW = "test-password"
auth_attempts = []


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        auth_attempts.append(password)
        return password == PW


def run(coro):
    return asyncio.run(coro)


async def start(key):
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[key])
    return server, server.sockets[0].getsockname()[1]


def opts(port):
    return {"port": port, "username": "u", "password": PW}


def test_pure():
    fp = "SHA256:" + "A" * 43
    assert hostkeys.valid_fingerprint(fp)
    assert not hostkeys.valid_fingerprint("SHA256:short")
    assert not hostkeys.valid_fingerprint("MD5:" + "A" * 43)
    assert not hostkeys.valid_fingerprint(None)
    assert hostkeys.normalize_fingerprint("  " + fp + "=\n") == fp
    assert hostkeys.normalize_fingerprint("sha256:" + "A" * 43) == fp
    assert hostkeys.normalize_fingerprint("SHA256:" + "A" * 43 + "\nextra") is None

    assert hostkeys.policy_for({}) == (None, False)
    assert hostkeys.policy_for({"host_key_fingerprint": fp}) == (fp, False)
    assert hostkeys.policy_for({"host_key_ignore": True}) == (None, True)
    # only a real boolean true opts out
    assert hostkeys.policy_for({"host_key_ignore": "true"}) == (None, False)
    assert hostkeys.policy_for({"host_key_ignore": 1}) == (None, False)
    # the older known_hosts setting no longer opts anyone out
    assert hostkeys.policy_for({"known_hosts": "ignore"}) == (None, False)
    # a malformed stored value counts as no pin (so the key is refused, not trusted)
    assert hostkeys.policy_for({"host_key_fingerprint": "garbage"}) == (None, False)

    other = "SHA256:" + "B" * 43
    # an edit cannot overwrite or remove the pin
    m = hostkeys.guard_config({"host_key_fingerprint": fp, "password": "p"},
                              {"host_key_fingerprint": other, "username": "x"},
                              target_changed=False)
    assert m["host_key_fingerprint"] == fp and m["password"] == "p" and m["username"] == "x"
    m = hostkeys.guard_config({"host_key_fingerprint": fp}, {}, target_changed=False)
    assert m["host_key_fingerprint"] == fp
    # a form that sends nothing for it, with no existing pin, adds none
    m = hostkeys.guard_config({}, {"host_key_fingerprint": other}, target_changed=False)
    assert "host_key_fingerprint" not in m
    # host or port change clears the pin
    m = hostkeys.guard_config({"host_key_fingerprint": fp}, {}, target_changed=True)
    assert "host_key_fingerprint" not in m
    # the refused-key note cannot be forged by an edit
    m = hostkeys.guard_config({}, {"host_key_refused": {"fingerprint": fp}}, target_changed=False)
    assert "host_key_refused" not in m
    # trusted (admin) editing: valid replaces, empty clears, invalid keeps nothing new
    m = hostkeys.guard_config({"host_key_fingerprint": fp}, {"host_key_fingerprint": other},
                              target_changed=True, trusted_incoming=True)
    assert m["host_key_fingerprint"] == other
    m = hostkeys.guard_config({"host_key_fingerprint": fp}, {"host_key_fingerprint": ""},
                              target_changed=False, trusted_incoming=True)
    assert "host_key_fingerprint" not in m
    m = hostkeys.guard_config({"host_key_fingerprint": fp}, {"host_key_fingerprint": "junk"},
                              target_changed=False, trusted_incoming=True)
    assert m["host_key_fingerprint"] == fp      # a placeholder does not wipe the pin
    m = hostkeys.guard_replacement({}, {"host_key_fingerprint": "junk", "a": 1},
                                   target_changed=False, trusted_incoming=True)
    assert m == {"a": 1}
    m = hostkeys.guard_replacement({"host_key_fingerprint": fp, "old": 1}, {"a": 1},
                                   target_changed=False, trusted_incoming=True)
    assert m == {"a": 1, "host_key_fingerprint": fp}
    # creating
    assert hostkeys.strip_new_pin({"host_key_fingerprint": fp, "a": 1}) == {"a": 1}

    # payload: grantee gets no accept button, owner does
    r = HostKeyRefused("changed", other, fp)
    assert hostkeys.refusal_payload(r, can_accept=False)["can_accept"] is False
    assert hostkeys.refusal_payload(r, can_accept=True)["can_accept"] is True
    assert "Host key changed" in hostkeys.refusal_payload(r, can_accept=False)["message"]
    assert hostkeys.refusal_payload(r, can_accept=True)["expected"] == fp
    u = HostKeyRefused("unpinned", other)
    assert "owner" in hostkeys.refusal_payload(u, can_accept=False)["message"]


async def _flow():
    key_a = asyncssh.generate_private_key("ssh-ed25519")
    fp_a = hostkeys.fingerprint_of(key_a)
    assert hostkeys.valid_fingerprint(fp_a), fp_a
    server, port = await start(key_a)

    # 1. unpinned: refused, fingerprint reported, no credential offered
    del auth_attempts[:]
    try:
        await connect_verified(["127.0.0.1"], opts(port), pinned=None, timeout=10)
        raise AssertionError("unpinned connect must be refused")
    except HostKeyRefused as e:
        assert e.state == "unpinned" and e.fingerprint == fp_a and e.expected is None
    assert auth_attempts == [], "password offered to an unverified host"

    # 2. pinned and matching: connects and authenticates
    conn, seen = await connect_verified(["127.0.0.1"], opts(port), pinned=fp_a, timeout=10)
    assert seen == fp_a and auth_attempts == [PW]
    conn.close()

    # 3. trust_unpinned (VOD auto-pin): connects, returns what to pin
    conn, seen = await connect_verified(
        ["127.0.0.1"], opts(port), pinned=None, trust_unpinned=True, timeout=10)
    assert seen == fp_a
    conn.close()
    # but a pin still wins over trust_unpinned
    server.close()
    await server.wait_closed()

    # 4. host key regenerated: refused as changed, no credential offered
    key_b = asyncssh.generate_private_key("ssh-ed25519")
    fp_b = hostkeys.fingerprint_of(key_b)
    server, port = await start(key_b)
    del auth_attempts[:]
    for trust in (False, True):
        try:
            await connect_verified(["127.0.0.1"], opts(port), pinned=fp_a,
                                   trust_unpinned=trust, timeout=10)
            raise AssertionError("changed key must be refused")
        except HostKeyRefused as e:
            assert e.state == "changed" and e.fingerprint == fp_b and e.expected == fp_a
    assert auth_attempts == [], "password offered to a host with a changed key"

    # 5. explicit opt-out connects whatever the key is
    conn, seen = await connect_verified(["127.0.0.1"], opts(port), pinned=fp_a, ignore=True, timeout=10)
    assert seen is None and auth_attempts == [PW]
    conn.close()

    # 6. a wrong password on a verified host is an ordinary auth error, not a key error
    server.close()
    await server.wait_closed()
    server, port = await start(key_a)
    try:
        await connect_verified(["127.0.0.1"], {**opts(port), "password": "bad"}, pinned=fp_a, timeout=10)
        raise AssertionError("bad password must fail")
    except asyncssh.PermissionDenied:
        pass
    server.close()
    await server.wait_closed()

    # 7. several key types on one server: the refusal names the type presented
    keys = [asyncssh.generate_private_key("ssh-ed25519"),
            asyncssh.generate_private_key("ssh-rsa", key_size=2048),
            asyncssh.generate_private_key("ecdsa-sha2-nistp256")]
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=keys)
    port = server.sockets[0].getsockname()[1]
    try:
        await connect_verified(["127.0.0.1"], opts(port), pinned=None, timeout=10)
        raise AssertionError("unpinned connect must be refused")
    except HostKeyRefused as e:
        shown = {hostkeys.fingerprint_of(k): k.algorithm.decode() for k in keys}
        assert e.fingerprint in shown and e.algorithm == shown[e.fingerprint], (e.fingerprint, e.algorithm)
        assert hostkeys.refusal_payload(e, can_accept=True)["algorithm"] == e.algorithm
        # pinning that fingerprint then connects, whatever the server's other keys are
        conn, seen = await connect_verified(["127.0.0.1"], opts(port), pinned=e.fingerprint, timeout=10)
        assert seen == e.fingerprint
        conn.close()
    server.close()
    await server.wait_closed()

    # 9. a server that presents an OpenSSH host certificate: the owner still
    # gets the plain key's fingerprint to accept, and a pin on it connects
    ca = asyncssh.generate_private_key("ssh-ed25519")
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    cert = ca.generate_host_certificate(host_key, "test-host", principals=["127.0.0.1"])
    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[(host_key, cert)])
    port = server.sockets[0].getsockname()[1]
    del auth_attempts[:]
    try:
        await connect_verified(["127.0.0.1"], opts(port), pinned=None, timeout=10)
        raise AssertionError("unpinned connect must be refused")
    except HostKeyRefused as e:
        assert e.state == "unpinned" and e.fingerprint == hostkeys.fingerprint_of(host_key), e.fingerprint
    assert auth_attempts == []
    conn, seen = await connect_verified(
        ["127.0.0.1"], opts(port), pinned=hostkeys.fingerprint_of(host_key), timeout=10)
    assert seen == hostkeys.fingerprint_of(host_key)
    conn.close()
    server.close()
    await server.wait_closed()

    # 8. a fresh key of another type is a different fingerprint
    key_c = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    assert hostkeys.fingerprint_of(key_c) not in (fp_a, fp_b)


# --- stored credentials only: no default keys, agent or ssh config ----------

import tempfile  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
pubkey_attempts = []


class _KeyAwareServer(_Server):
    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        pubkey_attempts.append(key.get_fingerprint())
        return False


async def _locked_flow():
    """A password-only or key connection must never offer the process user's
    own ~/.ssh keys, talk to its ssh-agent, or read its ssh config."""
    home = tempfile.mkdtemp()
    ssh_dir = os.path.join(home, ".ssh")
    os.makedirs(ssh_dir)
    own_key = asyncssh.generate_private_key("ssh-ed25519")
    own_key.write_private_key(os.path.join(ssh_dir, "id_ed25519"))
    with open(os.path.join(ssh_dir, "config"), "w") as f:
        f.write("Host *\n  ForwardAgent yes\n  IdentityFile %s\n" % os.path.join(ssh_dir, "id_ed25519"))
    agent_sock = os.path.join(home, "agent.sock")
    agent_hits = []

    async def agent_conn(reader, writer):
        # An agent that holds no keys: answer every request with FAILURE.
        agent_hits.append(1)
        try:
            while True:
                n = int.from_bytes(await reader.readexactly(4), "big")
                await reader.readexactly(n)
                writer.write(b"\x00\x00\x00\x01\x05")
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        writer.close()

    agent_server = await asyncio.start_unix_server(agent_conn, agent_sock)
    saved = {k: os.environ.get(k) for k in ("HOME", "SSH_AUTH_SOCK")}
    os.environ["HOME"], os.environ["SSH_AUTH_SOCK"] = home, agent_sock

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        _KeyAwareServer, "127.0.0.1", 0, server_host_keys=[host_key])
    port = server.sockets[0].getsockname()[1]
    fp = hostkeys.fingerprint_of(host_key)
    try:
        # Control: plain asyncssh, as the portal used to call it, does use them.
        del pubkey_attempts[:], agent_hits[:]
        c = await asyncssh.connect("127.0.0.1", port, username="u", password=PW, known_hosts=None)
        c.close()
        assert pubkey_attempts, "control: asyncssh defaults should offer the user's own key"
        assert agent_hits, "control: asyncssh defaults should contact the ssh-agent"

        own_fp = own_key.get_fingerprint()
        stored_key = asyncssh.generate_private_key("ssh-ed25519")
        for label, extra in (
                ("password only", {}),
                ("empty key list", {"client_keys": []}),
                ("stored key", {"client_keys": [stored_key]})):
            for ignore in (True, False):
                del pubkey_attempts[:], agent_hits[:]
                conn, _ = await connect_verified(
                    ["127.0.0.1"], {**opts(port), **extra}, pinned=fp, ignore=ignore, timeout=10)
                conn.close()
                await conn.wait_closed()
                assert own_fp not in pubkey_attempts, (label, ignore, "offered the process user's key")
                assert agent_hits == [], (label, ignore, "contacted the ssh-agent")
                if label == "stored key":
                    assert stored_key.get_fingerprint() in pubkey_attempts, "the stored key must be offered"
                else:
                    assert pubkey_attempts == [], (label, ignore, pubkey_attempts)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        server.close()
        await server.wait_closed()
        agent_server.close()


def test_locked_options():
    o = hostkeys.locked_client_options({"host": "h", "port": 22, "username": "u", "password": "p"})
    assert o["client_keys"] is None, "password-only must pass None, an empty list loads ~/.ssh/id_*"
    assert hostkeys.locked_client_options({"client_keys": []})["client_keys"] is None
    for k, v in hostkeys.LOCKED_OPTIONS.items():
        assert o[k] == v, k
    assert o["config"] == [] and o["agent_path"] is None and o["agent_forwarding"] is False
    assert o["gss_host"] is None and o["gss_kex"] is False and o["gss_auth"] is False
    assert o["host_based_auth"] is False
    # The values are what asyncssh turns into a locked-down client.
    parsed = asyncssh.SSHClientConnectionOptions(**o, known_hosts=None)
    assert parsed.client_keys is None
    assert parsed.agent_forward_path is None
    assert parsed.gss_host is None
    assert parsed.host_based_auth is False
    assert not parsed.client_host_keypairs
    assert parsed.pkcs11_provider is None
    # A caller cannot loosen it, or add an option the helper does not know.
    for bad in ({"agent_path": "/x"}, {"config": ()}, {"known_hosts": None}, {"gss_host": "h"}):
        try:
            hostkeys.locked_client_options({"host": "h", **bad})
            raise AssertionError("must reject " + str(bad))
        except ValueError:
            pass
    k = asyncssh.generate_private_key("ssh-ed25519")
    assert hostkeys.locked_client_options({"client_keys": [k]})["client_keys"] == [k]


def test_no_connect_site_bypasses_the_helper():
    """asyncssh.connect is called in hostkeys.py only, and each of the four
    connect sites goes through hostkeys.connect_verified."""
    import re
    skip = {"venv", "tests", "tools", "__pycache__", "node_modules", ".git"}
    hits = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(base, name)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if re.search(r"asyncssh\s*\.\s*(connect|connect_reverse|listen|scp|run_client|get_server_host_key|"
                          r"get_server_auth_methods|SSHClientConnectionOptions)\s*\(|SSHClientConnection\s*\(|"
                          r"from\s+asyncssh\s+import[^\n]*\b(connect|scp|run_client|get_server_host_key|get_server_auth_methods)\b", text):
                hits.append(os.path.relpath(path, ROOT))
    assert hits == ["hostkeys.py"], hits

    def source(name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as f:
            return f.read()

    assert "connect_verified(" in source("plugins/ssh.py")
    assert "connect_verified(" in source("sftp_browser.py")
    assert len(re.findall(r"hostkeys\.connect_verified\(", source("server.py"))) == 2


class _FakeConn:
    closed = False

    def close(self):
        self.closed = True


async def _no_validator_flow():
    """A connect that completes without the host-key validator being called
    (a GSS key exchange does that) is closed and refused when a key is required."""
    fake = _FakeConn()

    async def fake_dial(addrs, attempt, timeout):
        return fake

    real = hostkeys.try_each_address
    hostkeys.try_each_address = fake_dial
    try:
        for pinned, trust in (("SHA256:" + "A" * 43, False), (None, True)):
            fake.closed = False
            try:
                await connect_verified(["127.0.0.1"], opts(22), pinned=pinned, trust_unpinned=trust)
                raise AssertionError("an unverified connect must be refused")
            except asyncssh.HostKeyNotVerifiable:
                pass
            assert fake.closed, "the connection must be closed"
        # The explicit opt-out is the only case that skips the check.
        conn, seen = await connect_verified(["127.0.0.1"], opts(22), pinned=None, ignore=True)
        assert conn is fake and seen is None
    finally:
        hostkeys.try_each_address = real


async def _stale_seen_flow():
    """The validator ran for the first address, which then failed at connect
    level; the second address finished a handshake without calling it. The
    "validator never ran" check must be exact per attempt, so that connect is
    refused and closed instead of being reported with the first key."""
    key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
    fake = _FakeConn()
    calls = []
    real_connect = asyncssh.connect

    async def fake_connect(**kw):
        calls.append(kw["host"])
        if len(calls) == 1:
            kw["client_factory"]().validate_host_public_key(kw["host"], kw["host"], 22, key)
            raise ConnectionRefusedError("first address went away after its key was seen")
        return fake

    asyncssh.connect = fake_connect
    try:
        try:
            await connect_verified(["127.0.0.1", "127.0.0.2"], opts(22), pinned=None, trust_unpinned=True)
            raise AssertionError("a handshake that skipped the validator must be refused")
        except asyncssh.HostKeyNotVerifiable:
            pass
        assert calls == ["127.0.0.1", "127.0.0.2"], calls
        assert fake.closed, "the unverified connection must be closed"
    finally:
        asyncssh.connect = real_connect


def test_accept_token():
    T = hostkeys.HostKeyAcceptToken
    fp = "SHA256:" + "A" * 43
    tok = T.issue("secret", "connection", 5, 7, "h.example", 22, fp, now=1000)
    assert T.check("secret", tok, "connection", 5, 7, "h.example", 22, fp, now=1001)
    for args in (("service", 5, 7, "h.example", 22, fp), ("connection", 6, 7, "h.example", 22, fp),
                 ("connection", 5, 8, "h.example", 22, fp), ("connection", 5, 7, "other", 22, fp),
                 ("connection", 5, 7, "h.example", 2222, fp), ("connection", 5, 7, "h.example", 22, "SHA256:" + "B" * 43)):
        assert not T.check("secret", tok, *args, now=1001), args
    assert not T.check("other-secret", tok, "connection", 5, 7, "h.example", 22, fp, now=1001)
    assert not T.check("secret", tok, "connection", 5, 7, "h.example", 22, fp, now=1000 + T.TTL + 1)
    for junk in (None, "", "x", "12.", ".ab", "abc.def", 5):
        assert not T.check("secret", junk, "connection", 5, 7, "h.example", 22, fp, now=1001)
    assert not T.check("", tok, "connection", 5, 7, "h.example", 22, fp, now=1001)
    # the expiry cannot be extended without the secret
    exp, _, mac = tok.partition(".")
    assert not T.check("secret", f"{int(exp) + 999}.{mac}", "connection", 5, 7, "h.example", 22, fp, now=1001)


def main():
    test_pure()
    run(_flow())
    test_locked_options()
    test_no_connect_site_bypasses_the_helper()
    run(_locked_flow())
    run(_no_validator_flow())
    run(_stale_seen_flow())
    test_accept_token()
    print("test_hostkeys: ok")


main()
