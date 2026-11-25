"""The embedded browser page (GET /browser?connection=) does not tell a member who was only given a connection
where it points (1.24.1): no host or port in the HTML, the address bar shows the connection's name, and the
address-bar mapping works from the name. The owner and an administrator keep the address. The mapping script of
each page runs under Node with a stub document (tests/browser_target_harness.js); a real browser is not used here.

The real app on a loopback test server with a temporary database (tests/grant_harness.py). The connection points
at 169.254.169.254, which the host policy refuses to dial; the page does not dial anything.

Run: venv/bin/python tests/test_browser_page_target.py
"""

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grant_harness as h  # noqa: E402
from grant_harness import check, server  # noqa: E402

HERE = Path(__file__).resolve().parent
HOST = "169.254.169.254"
NAME = "wiki 'inner' \\"           # quotes and a trailing backslash: nothing of it may break the script
CONFIG = {"target_url": "http://10.9.8.7:8123/inner", "api_url": "http://10.9.8.7:9997"}


def harness(html, *secrets):
    node = shutil.which("node")
    if not node:
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write(html)
    try:
        res = subprocess.run([node, str(HERE / "browser_target_harness.js"), f.name, *secrets],
                             capture_output=True, text=True, timeout=60)
    finally:
        Path(f.name).unlink()
    return res


async def main():
    env = await h.boot(names=("owner", "bob", "adm", "mod"))
    db = env.db
    await db.set_user_role(env.uid["mod"], "admin")
    await env.sessions["mod"].close()
    env.sessions["mod"] = await h.login(env.base, "mod")
    owner, bob, adm, mod = (env.sessions[n] for n in ("owner", "bob", "adm", "mod"))
    pages = {}
    for label, cfg in (("plain", {"target_url": CONFIG["target_url"]}), ("browser mode", {**CONFIG, "browser_mode": True})):
        uuid = await db.create_user_connection(env.uid["owner"], NAME + ("" if label == "plain" else " "), "http_proxy", HOST, 8123, json.dumps(cfg))
        async with owner.post(f"{env.base}/api/connections/{uuid}/shares", json={"usernames": ["bob", "adm", "mod"]}) as r:
            check(f"{label}: shared", r.status == 200, str(r.status))
        for who in ("bob", "adm", "mod"):        # the first-open notice of a shared web connection (1.24.1), answered with Continue
            async with env.sessions[who].post(f"{env.base}/api/connections/{uuid}/notice") as r:
                assert r.status == 200, (who, r.status)

        async def page(sess):
            async with sess.get(f"{env.base}/browser?connection={uuid}") as r:
                return r.status, await r.text()

        st, text = await page(bob)
        check(f"{label}: the grantee gets the page", st == 200 and "url-input" in text, str(st))
        secrets = (HOST, "8123", "10.9.8.7", "9997", "inner/", "target_url")
        check(f"{label}: nothing of the target is anywhere in the grantee's page",
              all(s not in text for s in secrets), str([s for s in secrets if s in text]))
        check(f"{label}: the address bar shows the name", 'id="url-input" value="wiki &#x27;inner&#x27; \\' in text, text[text.find('id="url-input"'):][:120])
        check(f"{label}: the script says the target is hidden and holds no label literal",
              "const targetHidden = true;" in text and "'{{" not in text)
        pages[label, "bob"] = text
        res = harness(text, *secrets)
        if res is None:
            check("node is installed", False, "the mapping script could not be run")
        else:
            for ln in res.stdout.splitlines():
                if ln.startswith("FAIL"):
                    check(f"{label} grantee mapping: {ln}", False)
            check(f"{label}: the grantee's mapping works from the name alone ({res.stdout.count('ok:')} checks)",
                  res.returncode == 0, res.stdout[-400:] + res.stderr[-300:])
        for who, sess in (("the owner", owner), ("a superadmin", adm), ("an administrator", mod)):
            st, text = await page(sess)
            check(f"{label}: {who} keeps the address in the page", st == 200 and "http://169.254.169.254:8123" in text
                  and "const targetHidden = false;" in text, str(st))
            res = harness(text)
            if res is not None:
                check(f"{label}: {who}: the mapping of the address works", res.returncode == 0, res.stdout[-300:] + res.stderr[-200:])
        # the role is read now: an administrator demoted to member is blanked at once
        await db.set_user_role(env.uid["mod"], "user")
        st, text = await page(mod)
        check(f"{label}: a demoted administrator gets the hidden page", HOST not in text and "8123" not in text, str(st))
        await db.set_user_role(env.uid["mod"], "admin")
    await h.shutdown(env)
    h.finish("test_browser_page_target")


async def guarded():
    try:
        await asyncio.wait_for(main(), 100)
    except BaseException as e:
        print(f"FAIL: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        import os
        os._exit(1)


asyncio.run(guarded())
