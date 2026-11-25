"""Every stored secret of a connection is write-only.

GET /api/connections, GET /api/connections/{id} and /connect used to return Proxmox api_token, the http
connection's extra_headers, GitHub personal_token, client_secret and webhook_secret and the VPN pre_shared_key
in clear to any credential of the owner (only password, private_key, private_key_path, auth_header and psk were
hidden). Now each is replaced by a has_<key> flag. A test walks every plugin's config_schema so a field added
later that looks like a credential, or that is declared write-only, cannot be forgotten.

Run: venv/bin/python tests/test_connection_secrets.py
"""

import asyncio
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check  # noqa: E402

import connection_secrets as cs  # noqa: E402
import plugins  # noqa: E402
import server  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEADLINE = 120

SECRET_TOKENS = {"token", "secret", "password", "key", "header", "headers", "cookie", "cookies", "psk",
                 "community", "credential", "credentials", "auth", "passphrase"}
# Names that look like a credential and are not one, each with the reason
NOT_SECRET = {
    "host_key_ignore": "a boolean switch about verifying the server's identity",
    "host_key_fingerprint": "the public SHA256 fingerprint of the server's host key, not a credential",
    "auth_method": "which way to sign in (password or key), not a value",
    "client_id": "the public half of an OAuth app",
    "forward_headers": "names of client headers to forward; no values",
}
DIAL_TOKENS = {"host", "port", "ports", "url", "tls", "scheme", "target", "address", "addr", "endpoint", "server"}
# Names that look like an address and are not what the portal dials
NOT_DIAL = {
    "forwarded_host": "a boolean: send X-Forwarded-Host to the app",
    "host_key_ignore": "a boolean about host key verification",
    "host_key_fingerprint": "a public fingerprint the host key is compared with, not an address",
}


def schema_walk():
    plugins.load_builtin_plugins()
    props = {}
    for pname, plugin in plugins.get_all_plugins().items():
        for key, prop in ((plugin.info.config_schema or {}).get("properties") or {}).items():
            props[(pname, key)] = prop
    return props


def section_schema():
    props = schema_walk()
    check("the walk found the plugins' properties", len(props) > 40, str(len(props)))
    for (pname, key), prop in sorted(props.items()):
        tokens = set(key.lower().split("_"))
        looks = bool(tokens & SECRET_TOKENS)
        declared = prop.get("writeOnly") is True or prop.get("format") == "password"
        if looks:
            check(f"{pname}.{key}: a field that looks like a credential is a listed secret or named as harmless",
                  key in cs.SECRET_KEYS or key in NOT_SECRET, "add it to connection_secrets.SECRET_KEYS")
        if declared:
            check(f"{pname}.{key}: a field declared write-only is in SECRET_KEYS", key in cs.SECRET_KEYS)
        if key in cs.SECRET_KEYS:
            check(f"{pname}.{key}: a listed secret is declared writeOnly in the schema", prop.get("writeOnly") is True)
        if tokens & DIAL_TOKENS:
            check(f"{pname}.{key}: a field that looks like an address is a listed dial key or named as harmless",
                  key in cs.DIAL_KEYS or key in NOT_DIAL, "add it to connection_secrets.DIAL_KEYS")
    for key in NOT_SECRET:
        check(f"the harmless-name list does not hide a listed secret ({key})", key not in cs.SECRET_KEYS)
    check("the listed secrets cover the five that were hidden before",
          {"password", "private_key", "private_key_path", "auth_header", "psk"} <= cs.SECRET_KEYS)
    check("the new ones are listed", {"api_token", "extra_headers", "personal_token", "client_secret", "webhook_secret",
                                      "pre_shared_key"} <= cs.SECRET_KEYS)
    check("server uses the one list", server._SENSITIVE_CONFIG_FIELDS is cs.SECRET_KEYS)


def sentinel(key):
    return {"extra_headers": {"X-Api-Key": "SENT-extra-headers"}}.get(key, f"SENT-{key}")


async def section_answers():
    env = await h.boot(names=("owner", "adm"), superadmin=("adm",))
    db, owner = env.db, env.sessions["owner"]
    try:
        uuids = {}
        for key in sorted(cs.SECRET_KEYS):
            cfg = {"username": "u", key: sentinel(key)}
            uuids[key] = await db.create_user_connection(env.uid["owner"], f"c-{key}", "http", "93.184.216.34", 80,
                                                         json.dumps(cfg))
        seen = {}
        async with owner.get(f"{env.base}/api/connections") as r:
            seen["list"] = (r.status, await r.text())
        check("the list answers", seen["list"][0] == 200, str(seen["list"][0]))
        for key, u in uuids.items():
            async with owner.get(f"{env.base}/api/connections/{u}") as r:
                body = await r.text()
                detail = json.loads(body)
            check(f"{key}: the detail answer has no value", f"SENT-" not in body, body[:200])
            check(f"{key}: the detail answer says one is stored (has_{key})",
                  detail["config"].get(f"has_{key}") is True and key not in detail["config"], str(detail["config"]))
            check(f"{key}: the other config keys are unchanged", detail["config"].get("username") == "u")
            async with owner.get(f"{env.base}/api/connections/{u}/connect") as r:
                body = await r.text()
                st = r.status
            check(f"{key}: the connect answer has no value", st == 200 and "SENT-" not in body, f"{st} {body[:200]}")
        check("the list answer has no value of any secret", "SENT-" not in seen["list"][1], seen["list"][1][:200])
        check("an empty secret shows no flag", cs.redact({"api_token": ""}) == {})

        # An edit that sends nothing for a secret keeps it; one that sends a flag back does not store the flag
        u = uuids["api_token"]
        async with owner.put(f"{env.base}/api/connections/{u}", json={"name": "renamed", "config": {
                "username": "u2", "has_api_token": True, "has_extra_headers": True}}) as r:
            st = r.status
        row = await db.get_user_connection_by_uuid(u, env.uid["owner"])
        check("an edit that sends no value keeps the stored secret", st == 200 and row["config"].get("api_token") == "SENT-api_token",
              f"{st} {row['config']}")
        check("a has_<secret> flag sent back by a client is not stored",
              "has_api_token" not in row["config"] and "has_extra_headers" not in row["config"], str(row["config"]))
        async with owner.put(f"{env.base}/api/connections/{u}", json={"config": {"api_token": "SENT-new"}}) as r:
            st = r.status
        row = await db.get_user_connection_by_uuid(u, env.uid["owner"])
        check("an edit that sends a new value replaces it", st == 200 and row["config"].get("api_token") == "SENT-new", str(row["config"]))

        # A scoped key (read access only) reads the same flags and no value
        async with owner.post(f"{env.base}/api/api-keys", json={"name": "ro", "scopes": ["services:read"]}) as r:
            made = await r.json() if r.status in (200, 201) else {}
        raw = made.get("key") or made.get("api_key")
        if raw:
            import aiohttp
            async with aiohttp.ClientSession() as anon:
                async with anon.get(f"{env.base}/api/connections/{uuids['api_token']}", headers={"X-API-Key": raw}) as r:
                    body = await r.text()
                    st = r.status
            check("a scoped key reads a flag, not the token", st == 200 and "SENT-" not in body and "has_api_token" in body, f"{st} {body[:200]}")
        else:
            print("skip: no scoped key could be made in this setup", flush=True)
    finally:
        await h.shutdown(env)


def section_form():
    js = (ROOT / "static" / "js" / "user-connections.js").read_text()
    m = re.search(r"function populateDynamicConfigFields\(config\) \{.*?\n\}\n", js, re.S)
    check("populateDynamicConfigFields is present", m is not None)
    if not m:
        return
    script = """
const els = {};
function mk() { return {value: '', placeholder: '', dataset: {}, type: 'password'}; }
for (const k of ['api_token', 'auth_header', 'username']) els['connection-config-' + k] = mk();
global.document = {getElementById: (id) => els[id] || null};
""" + m.group(0) + """
populateDynamicConfigFields({username: 'u', has_api_token: true, has_auth_header: true, has_other: true});
console.log(JSON.stringify({u: els['connection-config-username'].value, t: els['connection-config-api_token'],
  a: els['connection-config-auth_header']}));
"""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "run.js"
        f.write_text(script)
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, timeout=30, cwd=d)
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check("node ran the function", bool(got), r.stderr[-300:])
    if got:
        check("a stored secret leaves its field empty with a 'stored' hint", got["t"]["value"] == ""
              and "stored" in got["t"]["placeholder"].lower() and "leave empty" in got["t"]["placeholder"].lower(), str(got["t"]))
        check("the hint is the same for every secret", got["a"]["placeholder"] == got["t"]["placeholder"])
        check("an ordinary field is filled", got["u"] == "u")


async def main():
    section_schema()
    await section_answers()
    section_form()


asyncio.run(asyncio.wait_for(main(), DEADLINE))
h.finish("test_connection_secrets")
