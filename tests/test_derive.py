"""Declarative key derivation — hkdf + ecdh var sources (no Python hook)."""
import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption)

from tatar_relay.derive import derive_hkdf, derive_ecdh
from tatar_relay.profile import Profile
from tatar_relay.engine import Engine
from tatar_relay.context import Context, HttpMessage
from tatar_relay.errors import DecryptError
from tatar_relay.variables import VarStore


# -- HKDF (RFC 5869 Appendix A.1, Test Case 1) ------------------------------
def test_hkdf_rfc5869_vector():
    vs = VarStore(); vs.set("ikm", "0b" * 22)
    out = derive_hkdf({"secret": "${ikm}",
                       "salt": "hex:000102030405060708090a0b0c",
                       "info": "hex:f0f1f2f3f4f5f6f7f8f9",
                       "length": 42, "hash": "sha256"}, vs)
    assert out.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")


def test_hkdf_missing_secret_is_config_error():
    with pytest.raises(DecryptError) as e:
        derive_hkdf({"length": 32}, VarStore())
    assert e.value.category == "config_error"


HKDF_PROFILE = '''name: hkdf-demo
scope: { hosts: ["api.example.com"] }
security: { allow_python_hooks: false }
vars:
  session_key:
    from: hkdf
    secret: "${shared}"
    salt: "app-salt"
    info: "v1"
    length: 32
request:
  envelope: { locate: [ { in: raw } ] }
  transform:
    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
    - as_json
'''


def _ctx(profile, **vars_):
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = profile.new_varstore(ctx)
    for k, v in vars_.items():
        vs.set(k, v)
    ctx.vars = vs
    return ctx


def test_hkdf_profile_roundtrip_is_declarative():
    # Loads with allow_python_hooks=false -> derivation is NOT treated as a hook.
    p = Profile.loads(HKDF_PROFILE)
    eng = Engine(p)
    ctx = _ctx(p, shared="00112233445566778899aabbccddeeff")
    sample = {"amount": 1000, "to": "acct"}
    wire = eng.encrypt("request", sample, ctx)
    assert eng.decrypt("request", wire, ctx) == sample


# -- ECDH -------------------------------------------------------------------
def test_ecdh_x25519_roundtrip():
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    a_priv = a.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    b_pub = b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    vs = VarStore(); vs.set("priv", a_priv); vs.set("pub", b_pub)
    secret = derive_ecdh({"curve": "x25519", "private": "${priv}",
                          "peer_public": "${pub}"}, vs)
    assert secret == b.exchange(a.public_key())
    assert len(secret) == 32


def test_ecdh_p256_roundtrip():
    a = ec.generate_private_key(ec.SECP256R1())
    b = ec.generate_private_key(ec.SECP256R1())
    a_priv = a.private_numbers().private_value.to_bytes(32, "big")
    b_pub = b.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    vs = VarStore(); vs.set("priv", a_priv); vs.set("pub", b_pub)
    secret = derive_ecdh({"curve": "p256", "private": "${priv}",
                          "peer_public": "${pub}"}, vs)
    assert secret == a.exchange(ec.ECDH(), b.public_key())


def test_ecdh_then_hkdf_chain():
    a = X25519PrivateKey.generate(); b = X25519PrivateKey.generate()
    a_priv = a.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    b_pub = b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    vs = VarStore(); vs.set("priv", a_priv); vs.set("pub", b_pub)
    vs.set_live("shared", lambda: derive_ecdh(
        {"curve": "x25519", "private": "${priv}", "peer_public": "${pub}"}, vs))
    key = derive_hkdf({"secret": "${shared}", "info": "aead", "length": 32}, vs)
    assert len(key) == 32


def test_ecdh_unsupported_curve_is_config_error():
    vs = VarStore(); vs.set("p", "00" * 32); vs.set("q", "00" * 32)
    with pytest.raises(DecryptError) as e:
        derive_ecdh({"curve": "p999", "private": "${p}", "peer_public": "${q}"}, vs)
    assert e.value.category == "config_error"
