"""Declarative key derivation: `hkdf` and `ecdh` var sources (Contract #1 vars).

These let a profile derive a symmetric key WITHOUT a Python hook, so an
untrusted / community profile can cover the common
"ECDH shared secret -> HKDF -> AES key" handshake declaratively.

    vars:
      shared:
        from: ecdh
        curve: x25519             # or p256
        private: "${my_priv}"     # our scalar  (hex / b64: / str:)
        peer_public: "${srv_pub}" # peer public key
      session_key:
        from: hkdf
        secret: "${shared}"       # or a captured secret directly
        salt: "app-salt"          # UTF-8 label by default; hex:/b64:/str: override
        info: "handshake v1"
        length: 32
        hash: sha256

Derived vars are LIVE (computed on first use) so they see `--var` / captured
secrets injected after the varstore is built. No `eval`, no hook. Authorized
testing only.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from .errors import DecryptError
from .variables import Renderer, coerce_key

_HASHES = {"sha256": hashes.SHA256, "sha1": hashes.SHA1, "sha512": hashes.SHA512}


def _material(tmpl, r, *, default: str):
    """Render a template to bytes.

    default 'auto' = hex-if-it-parses else UTF-8 (key-like material);
    default 'utf8' = UTF-8 label (salt/info). Explicit str:/hex:/b64: always win.
    """
    if tmpl is None:
        return None
    v = r.render(tmpl)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    s = str(v)
    if s.startswith(("str:", "hex:", "b64:")):
        return coerce_key(s, "derive")
    if default == "auto":
        return coerce_key(s, "derive", bare="auto")
    return s.encode("utf-8")


def derive_hkdf(spec: dict, varstore) -> bytes:
    r = Renderer(varstore)
    if spec.get("secret") is None:
        raise DecryptError(category="config_error", message="hkdf var: 'secret' is required")
    secret = _material(spec.get("secret"), r, default="auto")
    salt = _material(spec.get("salt"), r, default="utf8")
    info = _material(spec.get("info"), r, default="utf8")
    length = int(spec.get("length", 32))
    hname = str(spec.get("hash", "sha256")).lower()
    if hname not in _HASHES:
        raise DecryptError(category="config_error",
                           message=f"hkdf var: hash must be one of {tuple(_HASHES)}")
    try:
        return HKDF(algorithm=_HASHES[hname](), length=length,
                    salt=salt, info=info).derive(secret)
    except DecryptError:
        raise
    except Exception as e:  # noqa: BLE001
        raise DecryptError(category="config_error", message=f"hkdf var: {e}")


def derive_ecdh(spec: dict, varstore) -> bytes:
    r = Renderer(varstore)
    curve = str(spec.get("curve", "x25519")).lower()
    priv = _material(spec.get("private"), r, default="auto")
    pub = _material(spec.get("peer_public"), r, default="auto")
    if priv is None or pub is None:
        raise DecryptError(category="config_error",
                           message="ecdh var: 'private' and 'peer_public' are required")
    try:
        if curve == "x25519":
            sk = X25519PrivateKey.from_private_bytes(priv)
            pk = X25519PublicKey.from_public_bytes(pub)
            return sk.exchange(pk)
        if curve in ("p256", "secp256r1"):
            sk = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256R1())
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
            return sk.exchange(ec.ECDH(), pk)
    except DecryptError:
        raise
    except Exception as e:  # noqa: BLE001
        raise DecryptError(category="config_error", message=f"ecdh var: {e}")
    raise DecryptError(category="config_error",
                       message=f"ecdh var: unsupported curve {curve!r} (x25519, p256)")


DERIVERS = {"hkdf": derive_hkdf, "ecdh": derive_ecdh}
