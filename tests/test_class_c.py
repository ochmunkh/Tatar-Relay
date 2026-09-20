"""Class C — full symmetric envelope (body + encrypted headers).

Covers the three additive pieces:
  Gap 1  HttpMessage.set_header + header-envelope write-back
  Gap 3  strip_prefix codec (constant / length prefix)
  Gap 2  envelope.headers[] sub-pipelines (decrypt + re-encrypt headers in place)

All synthetic keys/data — proves the machinery is correct and reversible; no
real target or captured traffic is involved.
"""
import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore
from tatar_relay.errors import DecryptError, ProfileError


KEY = bytes(range(32))


def _gcm_b64(pt: bytes, key: bytes = KEY) -> str:
    """base64( 12-byte nonce || AES-GCM(ct||tag) ) — the shape aes_decrypt/gcm reads."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, pt, None)
    return base64.b64encode(nonce + ct).decode("ascii")


def _ctx(**kw) -> Context:
    c = Context(request=HttpMessage(host="api.example.com", **kw))
    vs = VarStore(); vs.set("session_key", KEY)
    c.vars = vs
    return c


# --------------------------------------------------------------------------
# Gap 1 — set_header + header-envelope write-back
# --------------------------------------------------------------------------

def test_set_header_replaces_case_insensitively():
    m = HttpMessage(headers={"X-Enc": "old"})
    m.set_header("x-enc", "new")
    assert m.headers == {"X-Enc": "new"}          # key case preserved, value replaced
    m.set_header("X-New", "v")
    assert m.header("x-new") == "v"                # added when absent


def test_header_envelope_edit_reseals():
    profile = """
name: header-envelope
scope: { hosts: [ "api.example.com" ] }
request:
  envelope: { locate: [ { in: header, name: "X-Enc" } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
    - as_json
"""
    eng = Engine(Profile.loads(profile))
    header_val = _gcm_b64(json.dumps({"op": "read"}).encode())
    ctx = _ctx(); ctx.request.headers = {"X-Enc": header_val, "X-Keep": "untouched"}

    plain = eng.decrypt("request", ctx.request.body, ctx)
    assert plain == {"op": "read"}

    plain["op"] = "transfer"
    eng.encrypt("request", plain, ctx)
    assert ctx.request.header("X-Enc") != header_val     # header was rewritten
    assert ctx.request.header("X-Keep") == "untouched"   # others left alone

    # the rewritten header decrypts back to the edited plaintext
    ctx2 = _ctx(); ctx2.request.headers = {"X-Enc": ctx.request.header("X-Enc")}
    assert eng.decrypt("request", b"", ctx2)["op"] == "transfer"


# --------------------------------------------------------------------------
# Gap 3 — strip_prefix
# --------------------------------------------------------------------------

def test_strip_prefix_constant_value_roundtrip():
    step = build_step({"strip_prefix": {"value": "0a0b0c0d", "encoding": "hex"}})
    prefix = bytes.fromhex("0a0b0c0d")
    body = b"the-real-ciphertext"
    assert step.forward(prefix + body, _ctx()) == body
    assert step.backward(body, _ctx()) == prefix + body   # stateless, from scratch


def test_strip_prefix_constant_missing_raises():
    step = build_step({"strip_prefix": {"value": "deadbeef", "encoding": "hex"}})
    with pytest.raises(DecryptError) as e:
        step.forward(b"no-such-prefix-here", _ctx())
    assert e.value.category == "config_error"


def test_strip_prefix_length_mode_roundtrip_in_flow():
    step = build_step({"strip_prefix": {"length": 4}})
    ctx = _ctx()
    blob = b"WRAP" + b"payload-bytes"
    stripped = step.forward(blob, ctx)          # captures "WRAP" on this ctx
    assert stripped == b"payload-bytes"
    assert step.backward(stripped, ctx) == blob  # restores the captured prefix


def test_strip_prefix_length_mode_from_scratch_raises():
    step = build_step({"strip_prefix": {"length": 4}})
    with pytest.raises(DecryptError) as e:
        step.backward(b"payload", _ctx())        # no prior decrypt -> nothing to restore
    assert e.value.category == "config_error"


def test_strip_prefix_needs_value_or_length():
    with pytest.raises(DecryptError):
        build_step({"strip_prefix": {}})


# --------------------------------------------------------------------------
# Gap 2 — full envelope: body AND encrypted headers
# --------------------------------------------------------------------------

FULL_ENVELOPE = """
name: full-envelope
scope: { hosts: [ "api.example.com" ] }
request:
  envelope:
    locate: [ { in: raw } ]
    headers:
      - name: "X-Meta"
        transform:
          - base64_decode
          - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
          - as_text
      - name: "X-Op"
        transform:
          - base64_decode
          - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
          - as_text
  transform:
    - base64_decode
    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
    - as_json
  reseal:
    - serialize: { mode: compact }
"""


def _snapshot(ctx) -> HttpMessage:
    """A fresh message carrying the just-written wire body + headers (like the next hop)."""
    return HttpMessage(host="api.example.com", headers=dict(ctx.request.headers))


def test_full_envelope_body_and_headers_roundtrip():
    eng = Engine(Profile.loads(FULL_ENVELOPE))
    ctx = _ctx()
    body_plain = {"amount": 100, "to": "AB12"}
    ctx.request.body = b""  # unused; body comes in as the wire arg
    ctx.request.headers = {
        "X-Meta": _gcm_b64(b"device=pixel;v=9"),
        "X-Op": _gcm_b64(b"LOGIN"),
        "X-Plain": "keep-me",
    }
    wire_in = _gcm_b64(json.dumps(body_plain).encode()).encode()

    plain = eng.decrypt("request", wire_in, ctx)
    assert plain == body_plain
    assert ctx.request.header("X-Meta") == "device=pixel;v=9"   # headers now readable
    assert ctx.request.header("X-Op") == "LOGIN"
    assert ctx.request.header("X-Plain") == "keep-me"           # untouched

    # edit both the body and one header, then reseal
    plain["amount"] = 999
    ctx.request.set_header("X-Op", "TRANSFER")
    wire_out = eng.encrypt("request", plain, ctx)

    # everything decrypts back to the edited values on the next hop
    nxt = _snapshot(ctx)
    ctx2 = _ctx(); ctx2.request = nxt; ctx2.vars = ctx.vars
    assert eng.decrypt("request", wire_out, ctx2) == {"amount": 999, "to": "AB12"}
    assert ctx2.request.header("X-Op") == "TRANSFER"
    assert ctx2.request.header("X-Meta") == "device=pixel;v=9"
    assert ctx2.request.header("X-Plain") == "keep-me"


def test_full_envelope_missing_header_is_skipped():
    eng = Engine(Profile.loads(FULL_ENVELOPE))
    ctx = _ctx()
    ctx.request.headers = {"X-Meta": _gcm_b64(b"only-meta")}  # X-Op absent
    wire = _gcm_b64(json.dumps({"a": 1}).encode()).encode()
    assert eng.decrypt("request", wire, ctx) == {"a": 1}
    assert ctx.request.header("X-Meta") == "only-meta"
    assert ctx.request.header("X-Op") == ""                   # absent stays absent


def test_header_subpipeline_python_is_guarded():
    """A python step inside a header sub-pipeline is still rejected when hooks are off."""
    profile = """
name: sneaky-header-hook
scope: { hosts: [ "api.example.com" ] }
request:
  envelope:
    locate: [ { in: raw } ]
    headers:
      - name: "X-Meta"
        transform:
          - python: { file: whatever.py, forward: f, backward: g }
  transform: [ as_json ]
"""
    with pytest.raises(ProfileError) as e:
        Profile.loads(profile)
    assert "allow_python_hooks" in str(e.value)
