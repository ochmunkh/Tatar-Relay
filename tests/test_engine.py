from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.variables import VarStore

CBC_PROFILE = """
name: test-cbc
scope: { hosts: [ "api.example.com" ], paths: [ "^/v2/.*" ] }
request:
  envelope: { locate: [ { in: json_field, field: "data" } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: cbc, key: "${session_key}", iv: { source: prefix, length: 16 } }
    - as_json
  reseal:
    - set:  { field: nonce, value: "${random_hex(16)}" }
    - sign: { algo: hmac_sha256, key: "${session_key}", input: "${payload_b64}", into: sign }
    - serialize: { mode: preserve }
"""


def _ctx(key):
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("session_key", key)
    c.vars = vs
    return c


def test_full_roundtrip_cbc():
    p = Profile.loads(CBC_PROFILE)
    eng = Engine(p)
    key = bytes(range(32))
    plain = {"amount": 1000, "to": "AB12", "nested": {"x": [1, 2, 3]}}
    ctx = _ctx(key)
    wire = eng.encrypt("request", plain, ctx)
    # wire is a JSON envelope with data/nonce/sign
    import json
    env = json.loads(wire)
    assert set(("data", "nonce", "sign")).issubset(env)
    # decrypt back
    back = eng.decrypt("request", wire, ctx)
    assert back == plain


def test_decrypt_then_edit_then_encrypt():
    p = Profile.loads(CBC_PROFILE)
    eng = Engine(p)
    key = bytes(range(32))
    ctx = _ctx(key)
    original = {"amount": 1000}
    wire = eng.encrypt("request", original, ctx)
    plain = eng.decrypt("request", wire, ctx)
    plain["amount"] = 90000
    wire2 = eng.encrypt("request", plain, ctx)
    assert eng.decrypt("request", wire2, ctx) == {"amount": 90000}


def test_hmac_signature_present_and_changes_with_payload():
    import json
    p = Profile.loads(CBC_PROFILE)
    eng = Engine(p)
    ctx = _ctx(bytes(range(32)))
    w1 = json.loads(eng.encrypt("request", {"amount": 1}, ctx))
    w2 = json.loads(eng.encrypt("request", {"amount": 2}, ctx))
    assert w1["sign"] != w2["sign"]
