"""A stored secret does not follow a moved target, for every connection type.

Before 1.24.1 only SPICE and Proxmox lost their stored secrets when the host or port changed; an http or embedded
browser connection kept auth_header and extra_headers when target_url changed, a GitHub connection kept its tokens,
a SPICE connection kept its password when tls_port changed. Now a change of anything that decides where the portal
dials (the row's host or port, the origin of target_url / api_url / webrtc_url / hls_url, tls_port, tls, a plugin
change of the type) removes every stored secret the same request does not send again, and the answer lists them.

Run: venv/bin/python tests/test_connection_repoint.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

import connection_secrets as cs  # noqa: E402

DEADLINE = 120
HDR = {"X-Api-Key": "extra-secret"}


def section_unit():
    old = {"target_url": "https://app.example/a", "tls": False}
    check("a path edit is not a move", not cs.dial_changed("h", 1, "h", 1, old, dict(old, target_url="https://APP.example:443/b?x=1")))
    check("a new scheme is a move", cs.dial_changed("h", 1, "h", 1, old, dict(old, target_url="http://app.example/a")))
    check("a new port in the URL is a move", cs.dial_changed("h", 1, "h", 1, old, dict(old, target_url="https://app.example:8443/a")))
    check("a new host in the URL is a move", cs.dial_changed("h", 1, "h", 1, old, dict(old, target_url="https://other.example/a")))
    check("the same host in another case is not a move", not cs.dial_changed("Host.Example", "22", "host.example", 22, {}, {}))
    check("tls_port is a move", cs.dial_changed("h", 1, "h", 1, {"tls_port": 5931}, {"tls_port": 5932}))
    check("tls switched on is a move", cs.dial_changed("h", 1, "h", 1, {}, {"tls": True}))
    check("an absent tls and tls false are the same", not cs.dial_changed("h", 1, "h", 1, {}, {"tls": False}))
    check("verify_ssl on to off is a move", cs.dial_changed("h", 1, "h", 1, {"verify_ssl": True}, {"verify_ssl": False}))
    check("verify_ssl on to absent is a move (absent means off)", cs.dial_changed("h", 1, "h", 1, {"verify_ssl": True}, {}))
    check("verify_ssl off to on is not a move", not cs.dial_changed("h", 1, "h", 1, {"verify_ssl": False}, {"verify_ssl": True}))
    check("verify_ssl absent to on is not a move", not cs.dial_changed("h", 1, "h", 1, {}, {"verify_ssl": True}))
    check("verify_ssl absent to off is not a move", not cs.dial_changed("h", 1, "h", 1, {}, {"verify_ssl": False}))
    check("verify_ssl on kept on is not a move", not cs.dial_changed("h", 1, "h", 1, {"verify_ssl": True}, {"verify_ssl": True}))
    check("an unparseable URL that changed is a move", cs.dial_changed("h", 1, "h", 1, {"target_url": "http://[bad"}, {"target_url": "http://[worse"}))
    out, cleared = cs.clear_on_move(moved=True, existing={"auth_header": "a"}, incoming={"auth_header": "new"},
                                    merged={"auth_header": "new", "extra_headers": HDR}, skip=())
    check("a secret sent again is kept and the others go", out == {"auth_header": "new"} and cleared == ["extra_headers"], f"{out} {cleared}")
    out, cleared = cs.clear_on_move(moved=False, existing={"auth_header": "a"}, incoming={}, merged={"auth_header": "a"})
    check("nothing is touched when nothing moved", out == {"auth_header": "a"} and cleared == [])


def section_form():
    js = (Path(__file__).resolve().parent.parent / "static" / "js" / "user-connections.js").read_text()
    check("the edit form tells the owner which stored values were removed", "stored_secrets_cleared" in js and "saved.stored_secrets_cleared.join" in js)


async def main():
    section_unit()
    section_form()
    env = await h.boot(names=("owner", "adm"), superadmin=("adm",))
    db, owner = env.db, env.sessions["owner"]
    uid = env.uid["owner"]
    n = [0]

    async def row(typ, cfg, host="93.184.216.34", port=8080):
        n[0] += 1
        return await db.create_user_connection(uid, f"r{n[0]}", typ, host, port, json.dumps(cfg))

    async def stored(u):
        return (await db.get_user_connection_by_uuid(u, uid))["config"]

    async def put(u, body):
        async with owner.put(f"{env.base}/api/connections/{u}", json=body) as r:
            return r.status, await r.json()

    try:
        base = {"target_url": "https://93.184.216.34:8443/app", "auth_header": "Bearer s3cret", "extra_headers": HDR, "timeout": 30}
        for typ in ("http", "https", "http_proxy", "grafana"):
            u = await row(typ, base)
            st, body = await put(u, {"config": {"target_url": "https://1.1.1.1:8443/app"}})
            c = await stored(u)
            check(f"{typ}: a new target_url removes auth_header and extra_headers", st == 200 and "auth_header" not in c
                  and "extra_headers" not in c and c.get("timeout") == 30 and c["target_url"].startswith("https://1.1.1.1"), f"{st} {c}")
            check(f"{typ}: the answer lists what was removed", body.get("stored_secrets_cleared") == ["auth_header", "extra_headers"], str(body))

        u = await row("http", base)
        st, body = await put(u, {"config": {"target_url": "https://93.184.216.34:8443/other/path?x=1"}})
        c = await stored(u)
        check("http: a changed path on the same origin keeps the secrets and says nothing",
              st == 200 and c.get("auth_header") == "Bearer s3cret" and c.get("extra_headers") == HDR and "stored_secrets_cleared" not in body, f"{c} {body}")
        st, body = await put(u, {"config": {"target_url": "http://93.184.216.34:8443/app"}})
        check("http: a new scheme removes the secrets", "auth_header" not in await stored(u) and "extra_headers" in body.get("stored_secrets_cleared", []), str(body))

        u = await row("http", base)
        st, body = await put(u, {"config": {"target_url": "https://1.1.1.1/", "auth_header": "Bearer fresh"}})
        c = await stored(u)
        check("http: a secret sent with the new target is kept, the other goes",
              c.get("auth_header") == "Bearer fresh" and "extra_headers" not in c and body.get("stored_secrets_cleared") == ["extra_headers"], f"{c} {body}")

        u = await row("http", base)
        st, body = await put(u, {"host": "1.1.1.1"})
        c = await stored(u)
        check("http: a new host column removes the secrets", "auth_header" not in c and "extra_headers" not in c, f"{c}")
        u = await row("http", base)
        st, body = await put(u, {"name": "renamed", "config": {"timeout": 45}})
        c = await stored(u)
        check("http: an edit that moves nothing keeps both and says nothing",
              c.get("auth_header") == "Bearer s3cret" and c.get("extra_headers") == HDR and "stored_secrets_cleared" not in body, f"{c} {body}")
        u = await row("http", base)
        st, body = await put(u, {"type": "grafana"})
        c = await stored(u)
        check("http: a type of the same plugin removes them too and lists them",
              st == 200 and "auth_header" not in c and "extra_headers" not in c and body.get("stored_secrets_cleared") == ["auth_header", "extra_headers"], f"{c} {body}")
        u = await row("http", base)
        st, body = await put(u, {"type": "grafana", "config": {"auth_header": "Bearer again"}})
        check("http: a secret sent with a type change is kept", (await stored(u)).get("auth_header") == "Bearer again", str(body))
        u = await row("http", base)
        st, body = await put(u, {"type": "http"})
        check("http: sending the same type is not a change", (await stored(u)).get("auth_header") == "Bearer s3cret" and "stored_secrets_cleared" not in body, str(body))

        vs = dict(base, verify_ssl=True)
        u = await row("http", vs)
        st, body = await put(u, {"config": {"verify_ssl": False}})
        c = await stored(u)
        check("http: turning verify_ssl off removes the secrets and lists them",
              st == 200 and "auth_header" not in c and "extra_headers" not in c and c.get("verify_ssl") is False
              and body.get("stored_secrets_cleared") == ["auth_header", "extra_headers"], f"{c} {body}")
        u = await row("http", vs)
        st, body = await put(u, {"config": {"verify_ssl": False, "auth_header": "Bearer fresh"}})
        check("http: a secret sent with verify_ssl off is kept", (await stored(u)).get("auth_header") == "Bearer fresh", str(body))
        u = await row("http", dict(base, verify_ssl=False))
        st, body = await put(u, {"config": {"verify_ssl": True}})
        check("http: turning verify_ssl on keeps the secrets", (await stored(u)).get("auth_header") == "Bearer s3cret" and "stored_secrets_cleared" not in body, str(body))
        u = await row("proxmox", {"api_token": "root@pam!t=x", "verify_ssl": True}, port=8006)
        st, body = await put(u, {"config": {"verify_ssl": False}})
        check("proxmox: turning verify_ssl off removes the token", "api_token" not in await stored(u) and body.get("stored_secrets_cleared") == ["api_token"], str(body))
        u = await row("http", base)
        st, body = await put(u, {"type": "vnc"})
        c = await stored(u)
        check("http: a type of another plugin removes them", "auth_header" not in c and "extra_headers" not in c, f"{c}")

        gh = {"personal_token": "ghp_x", "client_secret": "cs_x", "client_id": "cid", "webhook_secret": "wh_x"}
        u = await row("github", gh, host="93.184.216.34", port=443)
        st, body = await put(u, {"host": "1.1.1.1"})
        c = await stored(u)
        check("github: a new host removes the tokens and keeps the client id",
              st == 200 and c == {"client_id": "cid"} and body.get("stored_secrets_cleared") == ["client_secret", "personal_token", "webhook_secret"], f"{c} {body}")
        u = await row("github", gh, port=443)
        st, body = await put(u, {"config": {"default_org": "acme"}})
        check("github: an edit that moves nothing keeps the tokens", (await stored(u)).get("personal_token") == "ghp_x" and "stored_secrets_cleared" not in body)

        sp = {"password": "spicepw", "tls": True, "tls_port": 5931}
        u = await row("spice", sp, port=5930)
        st, body = await put(u, {"config": {"tls_port": 5932}})
        c = await stored(u)
        check("spice: a new tls_port removes the password", st == 200 and "password" not in c and c.get("tls_port") == 5932
              and body.get("stored_password_cleared") is True and body.get("stored_secrets_cleared") == ["password"], f"{c} {body}")
        u = await row("spice", {"password": "spicepw", "tls": False}, port=5930)
        st, body = await put(u, {"config": {"tls": True}})
        check("spice: switching TLS on removes the password", "password" not in await stored(u), str(body))

        u = await row("vpn_tunnel", {"mode": "socks", "pre_shared_key": "psk-x"}, port=1080)
        st, body = await put(u, {"port": 1081})
        check("vpn_tunnel: a new port removes the pre-shared key", "pre_shared_key" not in await stored(u) and body.get("stored_secrets_cleared") == ["pre_shared_key"], str(body))

        u = await row("proxmox", {"api_token": "root@pam!t=x", "password": "pw"}, port=8006)
        st, body = await put(u, {"host": "1.1.1.1"})
        check("proxmox: still cleared, still reported as before, now also listed",
              body.get("stored_password_cleared") is True and body.get("stored_secrets_cleared") == ["api_token", "password"], str(body))

        u = await row("ssh", {"username": "u", "auth_method": "key", "private_key": "KEY-BODY"}, port=22)
        st, body = await put(u, {"host": "1.1.1.1"})
        check("ssh: a new host also removes a stored private key and says so",
              "private_key" not in await stored(u) and body.get("stored_secrets_cleared") == ["private_key"], str(body))
        u = await row("ssh", {"username": "u", "auth_method": "key", "private_key": "KEY-BODY"}, port=22)
        st, body = await put(u, {"host": "1.1.1.1", "config": {"private_key": "NEW-KEY"}})
        check("ssh: a key sent with the new host is kept", (await stored(u)).get("private_key") == "NEW-KEY", str(body))
        u = await row("ssh", {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": "pw"}, port=22)
        st, body = await put(u, {"host": "1.1.1.1"})
        check("ssh: the stored password rule is unchanged (cleared, same flag) and the list names it",
              "password" not in await stored(u) and body.get("stored_password_cleared") is True and "password" in body.get("stored_secrets_cleared", []), str(body))

        # Choices that clear the stored SSH password without moving anything are not a move: the old flag only
        u = await row("ssh", {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": "pw"}, port=22)
        st, body = await put(u, {"config": {"credential_mode": "prompt"}})
        check("ssh: choosing Prompt each time answers stored_password_cleared and no move-style list",
              body.get("stored_password_cleared") is True and "stored_secrets_cleared" not in body and "password" not in await stored(u), str(body))
        u = await row("ssh", {"username": "u", "auth_method": "password", "credential_mode": "stored", "password": "pw"}, port=22)
        st, body = await put(u, {"config": {"username": "other"}})
        check("ssh: a changed username answers the old flag only", body.get("stored_password_cleared") is True and "stored_secrets_cleared" not in body, str(body))

        # Create stores what is sent (nothing is stored yet, so nothing can follow a move)
        async with owner.post(f"{env.base}/api/connections", json={"name": "new-http", "type": "http", "host": "93.184.216.34", "port": 80,
                                                                  "config": {"target_url": "http://93.184.216.34", "auth_header": "Bearer new"}}) as r:
            st, made = r.status, await r.json()
        check("create keeps the secret it was given", st == 201 and (await stored(made["id"])).get("auth_header") == "Bearer new", f"{st} {made}")
    finally:
        await h.shutdown(env)


asyncio.run(asyncio.wait_for(main(), DEADLINE))
h.finish("test_connection_repoint")
