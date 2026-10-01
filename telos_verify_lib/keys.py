"""Ed25519 public keys: loading, key acceptance, and signature checks.

The integrity-hash and chain paths never import this module's optional
dependency: `cryptography` is needed only to check an Ed25519 signature, and
HAVE_CRYPTO says whether it is installed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import pathlib

from .common import SIG_ALGORITHM

try:  # optional: only the signature path needs it
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised on machines without the dep
    HAVE_CRYPTO = False


def key_id(raw: bytes) -> str:
    """A short, stable label for a public key. Not a secret, not an authority."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# Ed25519 key acceptance (S1, S3). A public key is refused when (a) its 32 bytes
# are not a canonical point encoding (RFC 8032 section 5.1.3: y >= p, no x for
# that y, or x = 0 with the sign bit set), or (b) it has small order: [8]P is
# the identity, which holds for exactly the 8 torsion points. The signature
# R = identity, S = 0 verifies under the identity key for every message, and
# similar forgeries exist for every small-order key, so such a key proves
# nothing. The order test uses the RFC 8032 section 5.1.4 addition formulas;
# tests/test_small_order.py checks it against the 8 canonical small-order
# encodings (libsodium ge25519_has_small_order lists the same y values).
_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


class KeyRefused(ValueError):
    """A public key that must never be used to check a signature."""


def _edwards_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = t1 * 2 * _D * t2 % _P
    dd = z1 * 2 * z2 % _P
    e, f, g, hh = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * hh % _P, f * g % _P, e * hh % _P)


def key_refusal(raw: bytes):
    """Why a 32-byte Ed25519 public key is refused, or None if it is acceptable."""
    n = int.from_bytes(raw, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= _P:
        return "not a canonical point encoding (y is not reduced below p)"
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if v * x * x % _P == (-u) % _P:
        x = x * _SQRT_M1 % _P
    if v * x * x % _P != u:
        return "not a canonical point encoding (no curve point has this y)"
    if x == 0 and sign:
        return "not a canonical point encoding (x is 0 but the sign bit is set)"
    # P and -P have the same order, so the sign bit cannot change the answer below.
    pt = (x, y, 1, x * y % _P)
    for _ in range(3):
        pt = _edwards_add(pt, pt)
    if pt[0] == 0 and pt[1] == pt[2]:
        return "small-order point: signatures under this key can be forged without a private key"
    return None


def admit_key(raw: bytes) -> bytes:
    """Return `raw` if it is an acceptable Ed25519 public key; else raise KeyRefused."""
    why = key_refusal(raw)
    if why is not None:
        raise KeyRefused(f"refused Ed25519 public key: {why}")
    return raw


def load_public_key(path: pathlib.Path):
    """Load one trusted Ed25519 public key.

    Accepts PEM (SubjectPublicKeyInfo), or a file holding the 32 raw key bytes
    as base64 or hex. Returns (key_id, Ed25519PublicKey). Raises ValueError with
    a readable message; the caller decides that an unusable key is INCOMPLETE.
    """
    if not HAVE_CRYPTO:
        raise ValueError("the `cryptography` package is not installed")
    data = path.read_bytes()
    if b"-----BEGIN" in data:
        key = load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"{path}: PEM holds a {type(key).__name__}, not an Ed25519 public key")
        raw = admit_key(key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        return key_id(raw), key
    text = data.decode("utf-8", errors="strict").strip()
    raw = _canonical_key_text(text)
    if raw is None:
        raise ValueError(f"{path}: not a PEM, and not 32 raw key bytes as 64 contiguous hex "
                         "characters or canonical base64")
    return key_id(admit_key(raw)), Ed25519PublicKey.from_public_bytes(raw)


def _canonical_key_text(text: str):
    """32 key bytes from 64 contiguous hex characters or canonical base64, else None."""
    # One spelling per key: bytes.fromhex would take spaced pairs, and b64decode
    # would take unused trailing bits set, so both are checked by re-encoding.
    if len(text) == 64:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = None
        if raw is not None and raw.hex() == text.lower():
            return raw
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) == 32 and base64.b64encode(raw).decode("ascii") == text:
        return raw
    return None


def raw_public_key(b64text):
    """Ed25519 public key from canonical base64 of 32 bytes, or None.

    Raises KeyRefused for a small-order or non-canonical point.
    """
    if not isinstance(b64text, str):
        return None
    try:
        raw = base64.b64decode(b64text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != b64text:
        return None
    return admit_key(raw)


def refused_certificate(certs):
    """(index, KeyRefused) for the first certificate whose child_public_key is refused, or None.

    Called where certificates are loaded, for every certificate, whether or not a
    receipt uses it: an unused weak key is still forgery material in a trust set.
    Malformed keys are left to the per-receipt checks.
    """
    for n, c in enumerate(certs if isinstance(certs, list) else []):
        try:
            raw_public_key(c.get("child_public_key") if isinstance(c, dict) else None)
        except KeyRefused as e:
            return n, e
    return None


def ed25519_ok(pub_raw: bytes, sig_block, covers: str, message: str) -> bool:
    """True only if `sig_block` is a well-formed Ed25519 block verifying `message`."""
    if not (isinstance(sig_block, dict) and sig_block.get("algorithm") == SIG_ALGORITHM
            and sig_block.get("covers") == covers and isinstance(message, str)):
        return False
    value = sig_block.get("value")
    try:
        raw_sig = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
    except (binascii.Error, ValueError):
        return False
    if len(raw_sig) != 64 or base64.b64encode(raw_sig).decode("ascii") != value:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(raw_sig, message.encode("ascii"))
    except (InvalidSignature, ValueError, UnicodeError):
        return False
    return True


def verifies(pub, raw_sig: bytes, message: bytes) -> bool:
    """Whether `raw_sig` is a valid Ed25519 signature of `message` under `pub`."""
    try:
        pub.verify(raw_sig, message)
    except InvalidSignature:
        return False
    return True


def raw_bytes(pub) -> bytes:
    """The 32 raw bytes of a loaded Ed25519 public key."""
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
