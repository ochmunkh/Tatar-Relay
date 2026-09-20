import os
import pytest

from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore
from tatar_relay.errors import DecryptError


def _ctx():
    c = Context(request=HttpMessage(host="api.example.com"))
    c.vars = VarStore()
    return c


def test_nonce_body_hex_base64_roundtrip():
    step = build_step({"nonce_body": {"nonce_encoding": "hex", "nonce_length": 12,
                                      "body_encoding": "base64"}})
    raw = os.urandom(12) + b"ciphertext-and-tag-bytes"
    field = step.backward(raw, _ctx())          # -> "<hex nonce><b64 body>"
    assert isinstance(field, str)
    assert step.forward(field, _ctx()) == raw   # -> raw nonce||body


def test_nonce_body_matches_expected_shape():
    step = build_step({"nonce_body": {"nonce_encoding": "hex", "nonce_length": 12,
                                      "body_encoding": "base64"}})
    nonce = bytes(range(12))
    field = step.backward(nonce + b"abc", _ctx())
    assert field[:24] == nonce.hex()            # 12-byte nonce = 24 hex chars


def test_nonce_body_bad_encoding():
    with pytest.raises(DecryptError) as e:
        build_step({"nonce_body": {"nonce_encoding": "octal"}})
    assert e.value.category == "config_error"


def test_nonce_body_gcm_pipeline_no_hook():
    """The whole point: a hex-nonce + base64 GCM field, decrypted declaratively."""
    PROFILE = """
name: gcm-field
scope: { hosts: [ "api.example.com" ] }
request:
  envelope: { locate: [ { in: json_field, field: "data" } ] }
  transform:
    - nonce_body: { nonce_encoding: hex, nonce_length: 12, body_encoding: base64 }
    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
    - as_json
  reseal:
    - serialize: { mode: compact }
"""
    eng = Engine(Profile.loads(PROFILE))
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("session_key", bytes(range(32))); c.vars = vs
    plain = {"amount": 5000, "to": "AB12"}
    wire = eng.encrypt("request", plain, c)
    assert eng.decrypt("request", wire, c) == plain
