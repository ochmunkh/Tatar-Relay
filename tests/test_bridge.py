import base64
import json

from tatar_relay import Profile
from tatar_relay.bridge import BridgeService

PROFILE = """
name: bridge-demo
scope: { hosts: [ "api.example.com" ] }
request:
  envelope: { locate: [ { in: json_field, field: "data" } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: cbc, key: "${session_key}", iv: { source: prefix, length: 16 } }
    - as_json
  reseal:
    - serialize: { mode: preserve }
"""


def test_bridge_decrypt_encrypt_roundtrip():
    svc = BridgeService()
    svc.add_profile(Profile.loads(PROFILE))
    key_hex = bytes(range(32)).hex()

    # first make a wire by encrypting from scratch through the bridge is not a
    # method; craft one by decrypting a known-good wire we build via the engine.
    from tatar_relay import Engine, Context, HttpMessage
    from tatar_relay.variables import VarStore
    eng = Engine(svc.profiles["bridge-demo"])
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("session_key", bytes(range(32))); c.vars = vs
    wire = eng.encrypt("request", {"amount": 1000}, c)

    dec = svc.handle({"method": "decrypt", "profile": "bridge-demo",
                      "channel": "request", "wire": base64.b64encode(wire).decode(),
                      "vars": {"session_key": key_hex}, "flow_id": "f1"})
    assert dec["ok"] and dec["plaintext"] == {"amount": 1000}

    dec["plaintext"]["amount"] = 90000
    enc = svc.handle({"method": "encrypt", "profile": "bridge-demo",
                      "channel": "request", "plaintext": dec["plaintext"],
                      "ctx_token": dec["ctx_token"]})
    assert enc["ok"]
    rewire = base64.b64decode(enc["wire"])

    dec2 = svc.handle({"method": "decrypt", "profile": "bridge-demo",
                       "channel": "request", "wire": base64.b64encode(rewire).decode(),
                       "vars": {"session_key": key_hex}, "flow_id": "f2"})
    assert dec2["plaintext"] == {"amount": 90000}
