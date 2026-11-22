"""Reusing one ctx_token to seal many plaintexts — the Burp Intruder workflow.

The extension decrypts a real request once (getting a ctx_token), the operator
fuzzes the PLAINTEXT in Intruder, and every attempt is sealed with that token.
The bridge must reseal each one independently and keep enforcing scope.
"""
import base64

from tatar_relay.bridge import BridgeService
from tatar_relay.context import Context, HttpMessage
from tatar_relay.engine import Engine
from tatar_relay.profile import Profile

KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PROFILE = '''name: seal-demo
scope: { hosts: ["^api\\\\.example\\\\.com$"] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
    - as_json
'''


def _svc_and_token():
    p = Profile.loads(PROFILE)
    svc = BridgeService(default_vars={"session_key": KEY})
    svc.add_profile(p)
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = p.new_varstore(ctx); vs.set("session_key", bytes.fromhex(KEY)); ctx.vars = vs
    wire = Engine(p).encrypt("request", {"user": "alice", "amount": 1}, ctx)
    r = svc.handle({"method": "decrypt", "channel": "request",
                    "wire": base64.b64encode(wire).decode(), "host": "api.example.com"})
    assert r["ok"], r
    return svc, p, r["ctx_token"]


def _open(p, wire_b64):
    ctx = Context(request=HttpMessage(host="api.example.com"))
    vs = p.new_varstore(ctx); vs.set("session_key", bytes.fromhex(KEY)); ctx.vars = vs
    return Engine(p).decrypt("request", base64.b64decode(wire_b64), ctx)


def test_one_token_seals_many_payloads():
    svc, p, tok = _svc_and_token()
    payloads = ["' OR 1=1--", "<script>x</script>", "9" * 40]
    wires = []
    for pl in payloads:
        r = svc.handle({"method": "encrypt", "ctx_token": tok,
                        "plaintext": {"user": pl, "amount": 1}})
        assert r["ok"], r
        wires.append(r["wire"])
    assert len(set(wires)) == len(wires)                 # fresh nonce each time
    for pl, w in zip(payloads, wires):
        assert _open(p, w) == {"user": pl, "amount": 1}


def test_encrypt_enforces_scope_when_host_given():
    svc, _, tok = _svc_and_token()
    bad = svc.handle({"method": "encrypt", "ctx_token": tok, "plaintext": {"a": 1},
                      "host": "evil.example"})
    assert bad["ok"] is False and bad["error"]["category"] == "scope_violation"
    good = svc.handle({"method": "encrypt", "ctx_token": tok, "plaintext": {"a": 1},
                       "host": "api.example.com", "path": "/v2/pay"})
    assert good["ok"] is True


def test_unknown_token_is_refused():
    svc, _, _ = _svc_and_token()
    r = svc.handle({"method": "encrypt", "ctx_token": "t-" + "0" * 32, "plaintext": {}})
    assert r["ok"] is False and "ctx_token" in r["error"]["message"]
