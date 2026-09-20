"""Tests for the hmac_verify transform step.

Covers:
  - hex encoding (default)
  - base64 encoding
  - SHA-512 algo
  - wrong key  → signature_invalid
  - both field + expected → config_error at build time
  - neither field nor expected → config_error at build time
  - unsupported algo → config_error
  - field not in payload → config_error
  - payload not JSON when field= used → config_error
  - backward is a pass-through
  - strip_field=true (MAC covers body without sig field)
  - field= variant using an independent MAC input (avoids circular dependency)
  - engine round-trip: hmac_verify in pipeline, strip_field MAC
  - bi-directional: verify on forward, pass-through on backward
"""
import base64
import hashlib
import hmac
import json

import pytest

from tatar_relay.context import Context, HttpMessage
from tatar_relay.errors import DecryptError
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore

# ── helpers ──────────────────────────────────────────────────────────────────

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")   # 16-byte key


def ctx(key: bytes = KEY, **extra_vars) -> Context:
    c = Context()
    vs = VarStore()
    vs.set("session_key", key)
    for k, v in extra_vars.items():
        vs.set(k, v)
    c.vars = vs
    return c


def make_mac(key: bytes, msg: bytes, algo=hashlib.sha256, encoding="hex") -> str:
    digest = hmac.new(key, msg, algo).digest()
    if encoding == "base64":
        return base64.b64encode(digest).decode("ascii")
    return digest.hex()


# ── basic verify (hex, SHA-256) — ${payload} = raw step input ────────────────

def test_verify_hex_pass():
    """MAC covers the raw payload bytes (as delivered to this step)."""
    payload = b'{"amount":100,"currency":"MNT"}'
    mac = make_mac(KEY, payload)
    step = build_step({"hmac_verify": {
        "key":      "${session_key}",
        "input":    "${payload}",
        "expected": "${expected_mac}",
    }})
    result = step.forward(payload, ctx(expected_mac=mac))
    assert result == payload


def test_verify_hex_wrong_key():
    payload = b'{"amount":100}'
    mac = make_mac(KEY, payload)
    step = build_step({"hmac_verify": {
        "key":      "${session_key}",
        "input":    "${payload}",
        "expected": "${expected_mac}",
    }})
    wrong = bytes([x ^ 0xFF for x in KEY])
    with pytest.raises(DecryptError) as ei:
        step.forward(payload, ctx(wrong, expected_mac=mac))
    assert ei.value.category == "signature_invalid"


def test_verify_base64_encoding():
    payload = b'{"data":"test"}'
    mac = make_mac(KEY, payload, encoding="base64")
    step = build_step({"hmac_verify": {
        "key":      "${session_key}",
        "input":    "${payload}",
        "expected": "${mac_b64}",
        "encoding": "base64",
    }})
    result = step.forward(payload, ctx(mac_b64=mac))
    assert result == payload


def test_verify_sha512():
    payload = b'{"val":42}'
    mac = make_mac(KEY, payload, algo=hashlib.sha512)
    step = build_step({"hmac_verify": {
        "key":      "${session_key}",
        "input":    "${payload}",
        "expected": "${mac512}",
        "algo":     "sha512",
    }})
    step.forward(payload, ctx(mac512=mac))   # must not raise


# ── field= variant (signature inside the JSON payload) ───────────────────────
# Note: using input="${msg_input}" (an independent var) rather than "${payload}"
# because when input includes the sig field itself the MAC is circular.

def test_verify_field_pass():
    """MAC read from a JSON field; HMAC input is an independent var."""
    mac_input = b"canonical-body-data"
    mac = make_mac(KEY, mac_input)
    payload_json = json.dumps({"amount": 500, "signature": mac}).encode()

    step = build_step({"hmac_verify": {
        "key":   "${session_key}",
        "input": "${msg_input}",
        "field": "signature",
    }})
    step.forward(payload_json, ctx(msg_input=mac_input.decode("latin-1")))


def test_verify_field_wrong_sig():
    mac_input = b"canonical-body-data"
    payload_json = json.dumps({"amount": 500, "signature": "deadbeef" * 8}).encode()
    step = build_step({"hmac_verify": {
        "key":   "${session_key}",
        "input": "${msg_input}",
        "field": "signature",
    }})
    with pytest.raises(DecryptError) as ei:
        step.forward(payload_json, ctx(msg_input=mac_input.decode("latin-1")))
    assert ei.value.category == "signature_invalid"


# ── strip_field=true ─────────────────────────────────────────────────────────

def test_strip_field_verify():
    """MAC covers the JSON body with the sig field removed (canonical, sorted)."""
    body_no_sig = json.dumps({"amount": 500}, sort_keys=True, separators=(",", ":")).encode()
    mac = make_mac(KEY, body_no_sig)
    payload = json.dumps({"amount": 500, "signature": mac}).encode()

    step = build_step({"hmac_verify": {
        "key":         "${session_key}",
        "input":       "${payload}",
        "field":       "signature",
        "strip_field": True,
    }})
    step.forward(payload, ctx())   # must not raise


def test_strip_field_wrong_sig():
    body_no_sig = json.dumps({"amount": 500}, sort_keys=True, separators=(",", ":")).encode()
    wrong_mac = "aabb" * 16
    payload = json.dumps({"amount": 500, "signature": wrong_mac}).encode()

    step = build_step({"hmac_verify": {
        "key":         "${session_key}",
        "input":       "${payload}",
        "field":       "signature",
        "strip_field": True,
    }})
    with pytest.raises(DecryptError) as ei:
        step.forward(payload, ctx())
    assert ei.value.category == "signature_invalid"


# ── config errors ─────────────────────────────────────────────────────────────

def test_both_field_and_expected_raises():
    with pytest.raises(DecryptError) as ei:
        build_step({"hmac_verify": {
            "key":      "${session_key}",
            "input":    "${payload}",
            "field":    "sig",
            "expected": "${mac}",
        }})
    assert ei.value.category == "config_error"


def test_neither_field_nor_expected_raises():
    with pytest.raises(DecryptError) as ei:
        build_step({"hmac_verify": {
            "key":   "${session_key}",
            "input": "${payload}",
        }})
    assert ei.value.category == "config_error"


def test_unsupported_algo_raises():
    with pytest.raises(DecryptError) as ei:
        build_step({"hmac_verify": {
            "key":   "${session_key}",
            "input": "${payload}",
            "field": "sig",
            "algo":  "md5",
        }})
    assert ei.value.category == "config_error"


def test_field_missing_in_payload():
    payload = b'{"amount":100}'   # no 'signature' field
    step = build_step({"hmac_verify": {
        "key":   "${session_key}",
        "input": "${payload}",
        "field": "signature",
    }})
    with pytest.raises(DecryptError) as ei:
        step.forward(payload, ctx())
    assert ei.value.category == "config_error"


def test_payload_not_json_raises():
    payload = b"not-json-at-all"
    step = build_step({"hmac_verify": {
        "key":   "${session_key}",
        "input": "${payload}",
        "field": "sig",
    }})
    with pytest.raises(DecryptError) as ei:
        step.forward(payload, ctx())
    assert ei.value.category == "config_error"


# ── backward is pass-through ──────────────────────────────────────────────────

def test_backward_passthrough():
    payload = b'{"amount":100,"signature":"aabbcc"}'
    step = build_step({"hmac_verify": {
        "key":      "${session_key}",
        "input":    "${payload}",
        "expected": "${mac}",
    }})
    result = step.backward(payload, ctx(mac="aabbcc"))
    assert result == payload


# ── engine integration: verify in pipeline ───────────────────────────────────

def test_engine_verify_in_pipeline():
    """hmac_verify with strip_field=True in a raw-envelope pipeline.

    Wire: {"amount":999,"sig":"<hmac-hex>"}
    Forward: hmac_verify(strip_field) → as_json
    """
    from tatar_relay.engine import Engine
    from tatar_relay.profile import Profile

    key = bytes(range(16))

    # Canonical body without sig field
    body_no_sig = json.dumps({"amount": 999}, sort_keys=True, separators=(",", ":")).encode()
    mac = hmac.new(key, body_no_sig, hashlib.sha256).hexdigest()
    wire = json.dumps({"amount": 999, "sig": mac}).encode()

    profile_yaml = """
name: hmac-verify-engine
scope:
  hosts: ["api.example.com"]

request:
  envelope:
    locate:
      - in: raw
  transform:
    - hmac_verify:
        key: "${session_key}"
        input: "${payload}"
        field: sig
        strip_field: true
    - as_json
  reseal:
    - serialize:
        mode: compact
"""
    p = Profile.loads(profile_yaml)
    eng = Engine(p)

    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore()
    vs.set("session_key", key)
    c.vars = vs

    back = eng.decrypt("request", wire, c)
    assert back["amount"] == 999
    assert back["sig"] == mac


# ── bi-directional symmetry: verify forward + pass-through backward ───────────

def test_verify_sign_same_key_same_input():
    """Bi-directional: hmac_verify (forward) and reseal sign (backward) use
    the same key and input template — verifying the MAC the sign step produced."""
    import hmac as hmac_mod

    key = bytes(range(16))
    payload = b'{"amount":999}'
    mac = hmac_mod.new(key, payload, hashlib.sha256).hexdigest()

    step = build_step({"hmac_verify": {
        "key":      "${session_key}",
        "input":    "${payload}",
        "expected": "${sig}",
    }})

    # forward: verify succeeds
    step.forward(payload, ctx(key, sig=mac))

    # backward: pass-through (re-signing is reseal's job)
    result = step.backward(payload, ctx(key, sig=mac))
    assert result == payload
