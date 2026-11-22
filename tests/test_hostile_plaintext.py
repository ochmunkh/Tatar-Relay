"""Decrypted plaintext is attacker-influenced data (threat T10).

Relay decrypts ciphertext that came from, or can be shaped by, the target. The
plaintext then flows into the bridge reply, Burp editors, logs and Intruder
templates. This is the one trust boundary for it: whatever the plaintext holds
- control characters, NUL, line/paragraph separators, markup, huge blobs,
invalid UTF-8 - it must (a) survive a decrypt -> encrypt round trip unchanged,
(b) never break the bridge's single-line JSON framing, and (c) fail with a
structured error rather than an unclassified crash.

All values here are synthetic.
"""
import base64
import json

import pytest

from tatar_relay.bridge import BridgeService
from tatar_relay.context import Context, HttpMessage
from tatar_relay.engine import Engine
from tatar_relay.profile import Profile

KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
JSON_PROFILE = '''name: hostile-demo
scope: { hosts: ["^api\\\\.example\\\\.com$"] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
    - as_json
'''
TEXT_PROFILE = JSON_PROFILE.replace("name: hostile-demo", "name: hostile-text").replace(
    "    - as_json", "    - as_text")

HOSTILE = {
    "controls": "a\x00b\x01c\x07d\x1b[31mred\x7f",
    "newlines": "line1\r\nline2\nline3\rend",
    "separators": "x y z\u0085w",
    "markup": "<script>alert(1)</script>\"'><img src=x onerror=1>",
    "csv_formula": "=cmd|' /C calc'!A0",
    "bidi": "admin‮resu",
    "astral": "emoji \U0001F512 \U0010FFFF",
    "huge": "A" * (1024 * 1024),
}


def _ready(profile_src):
    p = Profile.loads(profile_src)
    svc = BridgeService(default_vars={"session_key": KEY})
    svc.add_profile(p)
    return p, svc


def _seal(p, value):
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = p.new_varstore(ctx)
    vs.set("session_key", bytes.fromhex(KEY))
    ctx.vars = vs
    return Engine(p).encrypt("request", value, ctx)


def _decrypt(svc, wire):
    return svc.handle({"method": "decrypt", "channel": "request",
                       "wire": base64.b64encode(wire).decode(),
                       "host": "api.example.com"})


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_json_values_round_trip_through_the_bridge(name):
    p, svc = _ready(JSON_PROFILE)
    value = {"memo": HOSTILE[name], "n": 1}
    r = _decrypt(svc, _seal(p, value))
    assert r["ok"], r
    assert r["plaintext"] == value
    # the reply must be one JSON line with no raw control bytes: line-based
    # consumers (logs, the Burp client) must not be able to be split by it
    framed = json.dumps(r)
    assert "\n" not in framed and "\r" not in framed
    assert all(ord(c) >= 0x20 for c in framed)
    assert json.loads(framed)["plaintext"] == value
    # and the same token reseals the hostile value back to identical plaintext
    e = svc.handle({"method": "encrypt", "ctx_token": r["ctx_token"], "plaintext": value})
    assert e["ok"], e
    again = _decrypt(svc, base64.b64decode(e["wire"]))
    assert again["ok"] and again["plaintext"] == value


def test_hostile_text_plaintext_round_trips():
    p, svc = _ready(TEXT_PROFILE)
    text = "".join(HOSTILE[k] for k in ("controls", "newlines", "separators", "markup"))
    r = _decrypt(svc, _seal(p, text))
    assert r["ok"] and r["plaintext"] == text
    assert "\n" not in json.dumps(r)


def test_invalid_utf8_plaintext_is_a_structured_error_not_a_crash():
    # Encrypt raw bytes that are not UTF-8 under the right key, then decrypt
    # through a text profile: the engine must classify the failure.
    p, svc = _ready(TEXT_PROFILE)
    raw_profile = TEXT_PROFILE.replace("    - as_text\n", "").replace(
        "name: hostile-text", "name: hostile-raw")
    rp = Profile.loads(raw_profile)
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = rp.new_varstore(ctx)
    vs.set("session_key", bytes.fromhex(KEY))
    ctx.vars = vs
    wire = Engine(rp).encrypt("request", b"\xff\xfe\x80 not utf-8 \xc3\x28", ctx)
    r = _decrypt(svc, wire)
    assert r["ok"] is False
    assert r["error"]["category"] != "internal", r
    assert isinstance(r["error"]["message"], str)
    json.dumps(r)                                   # the error itself is serialisable


def test_invalid_json_plaintext_is_a_structured_error():
    p, svc = _ready(JSON_PROFILE)
    raw = Profile.loads(JSON_PROFILE.replace("    - as_json\n", ""))
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = raw.new_varstore(ctx)
    vs.set("session_key", bytes.fromhex(KEY))
    ctx.vars = vs
    wire = Engine(raw).encrypt("request", b"{not json \x00\x1b", ctx)
    r = _decrypt(svc, wire)
    assert r["ok"] is False and r["error"]["category"] == "type_mismatch"
    assert "\n" not in json.dumps(r)


def test_error_messages_do_not_echo_hostile_plaintext_verbatim():
    # A decode error must not become a reflection channel for attacker bytes.
    p, svc = _ready(JSON_PROFILE)
    raw = Profile.loads(JSON_PROFILE.replace("    - as_json\n", ""))
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = raw.new_varstore(ctx)
    vs.set("session_key", bytes.fromhex(KEY))
    ctx.vars = vs
    marker = "ZZ-MARKER-" + "B" * 4096
    wire = Engine(raw).encrypt("request", marker.encode(), ctx)
    r = _decrypt(svc, wire)
    assert r["ok"] is False
    assert len(r["error"]["message"]) < 1024        # bounded, no full echo
