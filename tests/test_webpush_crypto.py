"""Web Push cryptography and policy, no server: the RFC 8291 appendix test vector (exact
ciphertext), a round trip through an independently written receiver, VAPID tokens checked
with PyJWT and with the receiver's own ECDSA verify, the endpoint allow-list, the payload
builder, key storage (encrypted, never regenerated over a bad one).

Run: venv/bin/python tests/test_webpush_crypto.py
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("JWT_SECRET", "x" * 64)

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import webpush as wp  # noqa: E402
import webpush_receiver as rx  # noqa: E402

failures = []


def check(name, passed, detail=""):
    print(("ok:   " if passed else "FAIL: ") + name + (f"  ({detail})" if detail and not passed else ""), flush=True)
    if not passed:
        failures.append(name)


def raises(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except wp.PushError:
        return True
    except Exception:
        return False
    return False


# --- RFC 8291 appendix A (values copied from the RFC text) -----------------------------
PLAINTEXT = rx.b64d("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24")
AS_PUBLIC = rx.b64d("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8")
AS_PRIVATE = rx.b64d("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
UA_PUBLIC = rx.b64d("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
UA_PRIVATE = rx.b64d("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
SALT = rx.b64d("DGv6ra1nlYgDCS1FRnbzlw")
AUTH = rx.b64d("BTBZMqHH6r4Tts7J_aSIgg")
HEADER = rx.b64d("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8")
CIPHERTEXT = rx.b64d("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ")

as_key = ec.derive_private_key(int.from_bytes(AS_PRIVATE, "big"), ec.SECP256R1())
ua_key = ec.derive_private_key(int.from_bytes(UA_PRIVATE, "big"), ec.SECP256R1())
check("RFC vector: the keys in the appendix match their public halves",
      wp.public_bytes(as_key) == AS_PUBLIC and wp.public_bytes(ua_key) == UA_PUBLIC)
body = wp.encrypt_aes128gcm(PLAINTEXT, UA_PUBLIC, AUTH, as_private=as_key, salt=SALT)
check("RFC vector: the 86 octet header is exact", body[:86] == HEADER and len(HEADER) == 86)
check("RFC vector: the ciphertext is exact", body[86:] == CIPHERTEXT, body[86:].hex())
check("RFC vector: the receiver reads it back to the plaintext",
      rx.decrypt(HEADER + CIPHERTEXT, ua_key, AUTH) == PLAINTEXT
      and PLAINTEXT == b"When I grow up, I want to be a watermelon")

# --- round trip with fresh keys through the independent receiver -----------------------
r = rx.new_receiver()
msg = json.dumps(wp.make_test_payload()).encode()
b1 = wp.encrypt_aes128gcm(msg, r["public"], r["auth"])
b2 = wp.encrypt_aes128gcm(msg, r["public"], r["auth"])
check("round trip: decrypts to the payload", rx.decrypt(b1, r["private"], r["auth"]) == msg)
check("fresh salt and key each time", b1 != b2 and b1[:16] != b2[:16] and b1[21:86] != b2[21:86])
try:
    rx.decrypt(b1, r["private"], os.urandom(16))
    wrong_ok = False
except Exception:
    wrong_ok = True
check("a wrong auth secret does not decrypt", wrong_ok)
check("oversized plaintext refused", raises(wp.encrypt_aes128gcm, b"x" * 5000, r["public"], r["auth"]))
check("a point that is not on the curve is refused",
      raises(wp.encrypt_aes128gcm, b"x", b"\x04" + b"\x01" * 64, r["auth"]))
check("a bad auth secret length is refused", raises(wp.encrypt_aes128gcm, b"x", r["public"], b"short"))
check("validate_keys takes a browser's strings and refuses junk",
      wp.validate_keys(rx.b64e(r["public"]), rx.b64e(r["auth"])) == (r["public"], r["auth"])
      and raises(wp.validate_keys, "AAAA", rx.b64e(r["auth"]))
      and raises(wp.validate_keys, rx.b64e(r["public"]), "AAAA")
      and raises(wp.validate_keys, rx.b64e(r["public"]), "not base64 !!"))

# --- VAPID ------------------------------------------------------------------------------
keys = wp.vapid_from_secret(wp.b64u((7).to_bytes(32, "big")))
check("vapid_from_secret rebuilds the pair from the stored secret", keys.public == wp.public_bytes(ec.derive_private_key(7, ec.SECP256R1())))
header = wp.vapid_authorization(keys, "https://fcm.googleapis.com", "https://portal.example", now=1_000_000)
check("VAPID header has the vapid scheme, t and k",
      header.startswith("vapid t=") and ", k=" in header and header.endswith(keys.public_b64))
token = header[len("vapid t="):].split(",")[0]
pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), rx.b64d(header.split("k=")[1]))
claims = jwt.decode(token, pub_obj, algorithms=["ES256"], audience="https://fcm.googleapis.com",
                    options={"verify_exp": False})
check("VAPID JWT verifies with PyJWT against the served key, aud/sub/exp right",
      claims["sub"] == "https://portal.example" and claims["exp"] == 1_000_000 + wp.VAPID_EXP_SECONDS
      and wp.VAPID_EXP_SECONDS <= 86400 and jwt.get_unverified_header(token) == {"typ": "JWT", "alg": "ES256"})
h64, c64, s64 = token.split(".")
check("VAPID signature verifies with the receiver's own ECDSA check",
      rx.ecdsa_ok(keys.public, (h64 + "." + c64).encode(), rx.b64d(s64)) and len(rx.b64d(s64)) == 64)
check("VAPID with another audience is a different token that fails for the first",
      not rx.ecdsa_ok(keys.public, (h64 + "." + c64 + "x").encode(), rx.b64d(s64)))
check("exp is capped at 24 hours",
      jwt.decode(wp.vapid_jwt(keys, "https://a.example", "https://p.example", now=0, lifetime=10 ** 9),
                 pub_obj, algorithms=["ES256"], audience="https://a.example",
                 options={"verify_exp": False})["exp"] == 86400)

# --- endpoint policy --------------------------------------------------------------------
ve = wp.validate_endpoint
good = ["https://fcm.googleapis.com/fcm/send/abc:def",
        "https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
        "https://web.push.apple.com/QGxx",
        "https://wns2-par02p.notify.windows.com/w/?token=abc",
        "https://fcm.googleapis.com:443/fcm/send/x",
        "https://FCM.GoogleAPIs.com./fcm/send/x"]
check("real push service endpoints are accepted", all(ve(u) == u for u in good), str([u for u in good if not raises(ve, u)]))
bad = ["http://fcm.googleapis.com/x", "https://evil.example/x", "https://fcm.googleapis.com.evil.example/x",
       "https://evilfcm.googleapis.com/x", "https://push.apple.com/x", "https://apple.com/x",
       "https://x.push.apple.com.evil.example/x", "https://fcm.googleapis.com@evil.example/x",
       "https://user:pw@fcm.googleapis.com/x", "https://fcm.googleapis.com:8443/x",
       "https://127.0.0.1/x", "https://[::1]/x", "https://169.254.169.254/x", "https://10.0.0.5/x",
       "https://localhost/x", "https://2130706433/x", "ftp://fcm.googleapis.com/x", "//fcm.googleapis.com/x",
       "https://fcm.googleapis.com/x#frag", "https://fcm.googleapis.com/x y", "https://fcm.googleapis.com/\\x",
       "https://fcm.googleapis.com/x\n", "", None, 5, "https://" + "a" * 800 + ".push.apple.com/x",
       "https://fcm.googleapis.com\\@evil.example/x", "javascript:alert(1)"]
check("outside the allow-list, wrong scheme or port, userinfo, IPs, junk: refused",
      all(raises(ve, u) for u in bad), str([u for u in bad if not raises(ve, u)]))
check("an extra host extends the list and nothing else",
      ve("https://push.example.org/x", ["push.example.org"]) and raises(ve, "https://other.example.org/x", ["push.example.org"])
      and ve("https://a.b.example.org/x", ["*.example.org"]) and raises(ve, "https://example.org/x", ["*.example.org"]))
check("the loopback sink is accepted only with its port set",
      raises(ve, "http://127.0.0.1:5555/x") and ve("http://127.0.0.1:5555/x", (), 5555)
      and raises(ve, "http://127.0.0.1:5556/x", (), 5555) and raises(ve, "http://localhost:5555/x", (), 5555)
      and raises(ve, "https://127.0.0.1:5555/x", (), 5555) and raises(ve, "http://127.0.0.2:5555/x", (), 5555))
check("extra-host list parser: good entries kept, bad refused",
      wp.parse_extra_hosts("a.example.org, *.b.example.org\nC.Example.org.") == ["a.example.org", "*.b.example.org", "c.example.org"]
      and all(raises(wp.parse_extra_hosts, x) for x in
              ("127.0.0.1", "localhost", "10.0.0.1", "intranet", "*.com", "*.", "a b!.example.org", "169.254.169.254",
               "0x7f000001", "x.internal", "[::1]")))
check("allow_test_sink is off by default", wp._test_sink_port is None)

# --- payloads ---------------------------------------------------------------------------
check("build_payload keeps type, title, body, url",
      wp.build_payload("chat.mention", "New mention", "Open the portal", "/chat?c=3")
      == {"type": "chat.mention", "title": "New mention", "body": "Open the portal", "url": "/chat?c=3"})
check("an absolute, protocol-relative, backslash or control-character URL is refused",
      all(raises(wp.build_payload, "x", "t", "b", u) for u in
          ("https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)", "chat", "", "/a\nb")))
check("a dot segment (plain or encoded) or encoded slash that collapses to //host is refused; a query is kept",
      all(raises(wp.build_payload, "x", "t", "b", u) for u in
          ("/a/..//evil.example", "/.//evil.example", "/a/%2E%2e//evil.example", "/a/./b", "/a%2F%2Fevil.example", "/a%5cb"))
      and wp.build_payload("x", "t", "b", "/chat?c=3&x=..//a#f")["url"] == "/chat?c=3&x=..//a#f")
check("bad type or empty title refused", raises(wp.build_payload, "Bad Type", "t") and raises(wp.build_payload, "x", "  "))
check("long text is cut, control characters removed",
      len(wp.build_payload("x", "t" * 500, "b" * 500)["title"]) == 80
      and wp.build_payload("x", "a\x00b\u202ec", "")["title"] == "abc")

# --- key storage ------------------------------------------------------------------------
async def storage():
    import database
    d = tempfile.mkdtemp()
    db = database.Database(str(Path(d) / "t.db"))
    await db.connect()
    try:
        k1 = await wp.get_vapid(db)
        raw = await db.get_setting(wp.SETTING_PRIVATE)
        check("a key pair is generated on first use and the private key is stored encrypted",
              k1 is not None and raw.startswith("enc:") and rx.b64e(k1.private.private_numbers().private_value.to_bytes(32, "big")) not in raw)
        check("the public key is stored too and matches", await db.get_setting(wp.SETTING_PUBLIC) == k1.public_b64)
        k2 = await wp.get_vapid(db)
        check("the same key is returned afterwards", k2.public == k1.public)
        both = await asyncio.gather(*(wp.get_vapid(db) for _ in range(5)))
        check("concurrent first use gives one key", all(b.public == k1.public for b in both))
        await db.set_setting(wp.SETTING_PRIVATE, "enc:garbage")
        check("an unreadable stored key keeps push off and is not replaced",
              await wp.get_vapid(db) is None and await db.get_setting(wp.SETTING_PRIVATE) == "enc:garbage")
        await db.set_setting(wp.SETTING_PRIVATE, '{"d":"plain"}')
        check("a stored key that is not encrypted is refused", await wp.get_vapid(db) is None)
    finally:
        await db.close()


asyncio.run(storage())

if failures:
    print(f"\ntest_webpush_crypto: {len(failures)} FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\ntest_webpush_crypto: all checks passed")
