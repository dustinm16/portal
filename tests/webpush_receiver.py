"""The receiving side of Web Push, written separately from webpush.py so that a mistake in
the sender cannot be mirrored here: what a browser does with a message (RFC 8291 section 4
and RFC 8188), plus a decrypting fake push service for tests.

Used by tests/test_webpush_*.py and tools/smoke_checks/check_push.py.
"""

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64d(text: str) -> bytes:
    t = "".join(text.split())
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) from the HMAC primitive, not from a library class."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def new_receiver():
    """A user agent key pair and auth secret, as a browser's PushSubscription holds them."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return {"private": key, "public": pub, "auth": os.urandom(16),
            "p256dh": b64e(pub), "auth_b64": None}


def decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth_secret: bytes) -> bytes:
    """aes128gcm of RFC 8188 with the key derivation of RFC 8291 section 3.4 (receiver side)."""
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_public = body[21:21 + idlen]
    ciphertext = body[21 + idlen:]
    assert idlen == 65 and rs >= 18, "bad header"
    ua_public = ua_private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    as_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public)
    secret = ua_private.exchange(ec.ECDH(), as_key)
    ikm = hkdf(auth_secret, secret, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    plain = AESGCM(cek).decrypt(nonce, ciphertext, None)
    assert plain.endswith(b"\x02"), "missing last-record delimiter"
    return plain[:-1]


def ecdsa_ok(public_raw: bytes, signing_input: bytes, raw_sig: bytes) -> bool:
    """Verify a raw r||s ES256 signature against an uncompressed public key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_raw)
    r, s = int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
