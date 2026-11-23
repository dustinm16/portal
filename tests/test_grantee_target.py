"""A connection shared with a member carries no target: host and port are null and config is empty in
GET /api/connections (with and without ?type=), GET /api/connections/{id} and the connection object of
GET /api/connections/{id}/connect. The owner and an administrator (role admin or superadmin) see the
full row, and the server still connects by id for the grantee (the stored row is untouched).

The real app on a loopback test server with a temporary database (tests/grant_harness.py). The
connection points at 169.254.169.254, which the host policy refuses without dialling.

Run: venv/bin/python tests/test_grantee_target.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402

HOST = "169.254.169.254"
CONFIG = {"target_url": "http://10.9.8.7:8123/inner", "api_url": "http://10.9.8.7:9997", "hls_url": "http://10.9.8.7:8888/x",
          "username": "svc", "password": "hunter2-secret", "browser_mode": True}


async def main():
    env = await h.boot(names=("owner", "bob", "carol", "adm", "mod", "dave"))
    db = env.db
    await db.set_user_role(env.uid["mod"], "admin")
    await env.sessions["mod"].close()
    env.sessions["mod"] = await h.login(env.base, "mod")
    owner, bob, adm, mod, dave = (env.sessions[n] for n in ("owner", "bob", "adm", "mod", "dave"))
    uuid = await db.create_user_connection(env.uid["owner"], "inner", "http_proxy", HOST, 8123, json.dumps(CONFIG))
    own_uuid = await db.create_user_connection(env.uid["bob"], "bobs", "ssh", "198.51.100.7", 2222, "{}")
    async with owner.post(f"{env.base}/api/connections/{uuid}/shares",
                          json={"usernames": ["bob", "adm", "mod"], "expires_in": "7d"}) as r:
        check("the owner shares it with a member, an administrator and a superadmin", r.status == 200, str(r.status))
    ssh_cfg = {"username": "svc", "credential_mode": "stored", "password": "S3cret-pw", "host_key_fingerprint": "SHA256:abc",
               "auth_method": "password", "shell": "/bin/zsh"}
    ssh_uuid = await db.create_user_connection(env.uid["owner"], "stored", "ssh", "198.51.100.9", 2200, json.dumps(ssh_cfg))
    async with owner.post(f"{env.base}/api/connections/{ssh_uuid}/shares", json={"usernames": ["bob"]}) as r:
        check("the owner shares an SSH connection with a stored password", r.status == 200, str(r.status))

    async def get(sess, path):
        async with sess.get(env.base + path) as r:
            text = await r.text()
            return r.status, text, (json.loads(text) if r.status == 200 else None)

    def bare(c):
        return c["host"] is None and c["port"] is None and c["config"] == {}

    # ---- the grantee -----------------------------------------------------------------------------------------------
    for label, path in (("list", "/api/connections"), ("filtered list", "/api/connections?type=http_proxy")):
        st, text, data = await get(bob, path)
        mine = {c["id"]: c for c in data["connections"]}
        c = mine.get(uuid)
        check(f"grantee {label}: the shared connection has host, port and config blanked (keys kept)",
              st == 200 and c is not None and bare(c), str(c))
        check(f"grantee {label}: nothing of the target is anywhere in the answer",
              all(s not in text for s in (HOST, "10.9.8.7", "8123", "target_url", "hunter2", "api_url", "hls_url")), text[:300])
        check(f"grantee {label}: name, type, owner and share expiry are still there",
              c["name"] == "inner" and c["type"] == "http_proxy" and c["shared"] == 1 and c["owner_username"] == "owner"
              and c["share_expires_in"] is not None and "prefs" in c, str(c))
    st, text, data = await get(bob, "/api/connections")
    own = {c["id"]: c for c in data["connections"]}.get(own_uuid)
    check("grantee list: the grantee's own connection keeps its host and port",
          own is not None and own["host"] == "198.51.100.7" and own["port"] == 2222, str(own))
    st, text, c = await get(bob, f"/api/connections/{uuid}")
    check("grantee detail: blanked", st == 200 and bare(c) and c["name"] == "inner" and HOST not in text and "10.9.8.7" not in text, text[:300])
    st, text, d = await get(bob, f"/api/connections/{uuid}/connect")
    check("grantee connect: the connection object is blanked, the websocket url is there",
          st == 200 and bare(d["connection"]) and d["connection"]["type"] == "http_proxy" and d["connection"]["name"] == "inner"
          and d["websocket_url"] == f"/ws/user-connection/{uuid}" and HOST not in text and "10.9.8.7" not in text, text[:300])
    st, text, own_detail = await get(bob, f"/api/connections/{own_uuid}")
    check("grantee detail of an own connection is complete", st == 200 and own_detail["host"] == "198.51.100.7")

    st, text, data = await get(bob, "/api/connections")
    c = {x["id"]: x for x in data["connections"]}[ssh_uuid]
    check("grantee list: of the config only has_stored_password and credential_mode stay (the documented answer), no user name, pin or shell",
          c["host"] is None and c["port"] is None and c["config"] == {"has_stored_password": True, "credential_mode": "stored"}
          and "198.51.100.9" not in text and "S3cret" not in text, str(c))
    st, text, c = await get(bob, f"/api/connections/{ssh_uuid}")
    check("grantee detail: the same", c["config"] == {"has_stored_password": True, "credential_mode": "stored"} and c["host"] is None, str(c))

    # ---- the server still connects by id ---------------------------------------------------------------------
    row = await db.get_accessible_connection(uuid, env.uid["bob"])
    check("the stored row the server connects with still has the target",
          row["host"] == HOST and row["port"] == 8123 and row["config"]["target_url"] == CONFIG["target_url"], str(row))
    async with bob.get(f"{env.base}/proxy/{uuid}/", allow_redirects=False) as r:
        check("the grantee reaches the proxy by id (the host policy answers, not 404)", r.status == 403, str(r.status))
    async with dave.get(f"{env.base}/proxy/{uuid}/", allow_redirects=False) as r:
        check("a member without a share still gets 404", r.status == 404, str(r.status))
    st, text, _ = await get(dave, "/api/connections")
    check("a member without a share sees nothing of it", uuid not in text and HOST not in text)

    # ---- who still sees the target ------------------------------------------------------------------------------
    st, text, data = await get(owner, "/api/connections")
    c = {x["id"]: x for x in data["connections"]}[uuid]
    check("the owner keeps host, port and the non-secret config (the password stays redacted)",
          c["host"] == HOST and c["port"] == 8123 and c["config"]["target_url"] == CONFIG["target_url"]
          and c["config"]["has_password"] is True and "hunter2" not in text, str(c))
    for who, sess in (("a superadmin", adm), ("an administrator", mod)):
        st, text, data = await get(sess, "/api/connections")
        c = {x["id"]: x for x in data["connections"]}[uuid]
        check(f"{who} who was given the connection keeps host, port and config (list)",
              c["host"] == HOST and c["port"] == 8123 and c["config"]["target_url"] == CONFIG["target_url"], str(c))
        st, text, c = await get(sess, f"/api/connections/{uuid}")
        check(f"{who}: detail has the target", st == 200 and c["host"] == HOST and c["config"]["api_url"] == CONFIG["api_url"])
        st, text, d = await get(sess, f"/api/connections/{uuid}/connect")
        check(f"{who}: connect has the target", st == 200 and d["connection"]["host"] == HOST)

    # ---- the role is read now, not from the token --------------------------------------------------------------
    await db.set_user_role(env.uid["mod"], "user")
    st, text, data = await get(mod, "/api/connections")
    c = {x["id"]: x for x in data["connections"]}[uuid]
    check("an administrator demoted to member is blanked at once", bare(c), str(c))

    # ---- the clients of a grantee do not print a missing address --------------------------------------------------
    root = Path(__file__).resolve().parent.parent
    portal_js = (root / "static/js/portal.js").read_text()
    files_html = (root / "static/files.html").read_text()
    check("the command palette shows the owner for a shared connection instead of host:port",
          "c.shared ? `shared by ${c.owner_username || '?'} (${c.type})`" in portal_js)
    check("the Files connection list names the owner for a shared connection instead of host:port",
          "c.shared ? `${c.name} (shared by ${c.owner_username || '?'})`" in files_html)

    await h.shutdown(env)


asyncio.run(main())
h.finish("test_grantee_target")
