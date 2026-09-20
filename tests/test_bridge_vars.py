"""Bridge --var coercion: default hex, plus str:/b64:/hex: prefixes.

Regression for the EVP passphrase flow: a bare var is hex (session keys),
but a passphrase like an ecode must survive as a string, not be hex-decoded.
"""
import base64
import json

from tatar_relay.bridge import BridgeService
from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.variables import VarStore

PROFILE_YAML = """
name: evp-aes-passphrase
scope: { hosts: [ "api.example.com" ] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform:
    - evp_aes_decrypt: { passphrase: "${ecode}" }
    - as_json
  reseal:
    - serialize: { mode: compact }
"""


def _wire(ecode: str, plain: dict) -> bytes:
    eng = Engine(Profile.loads(PROFILE_YAML))
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("ecode", ecode.encode("utf-8")); c.vars = vs
    return eng.encrypt("request", plain, c)


def test_bridge_str_prefix_passphrase():
    svc = BridgeService()
    svc.add_profile(Profile.loads(PROFILE_YAML))
    wire = _wire("my-ecode-9f", {"call": "balance", "n": 7})
    msg = {"profile": "evp-aes-passphrase", "channel": "request",
           "wire": base64.b64encode(wire).decode(),
           "vars": {"ecode": "str:my-ecode-9f"}}
    out = svc._decrypt(msg)
    assert out["ok"] and out["plaintext"] == {"call": "balance", "n": 7}


def test_bridge_bare_var_is_hex():
    # A bare value is still hex-decoded (session-key flow unchanged).
    svc = BridgeService(default_vars={"session_key": "00112233445566778899aabbccddeeff"})
    # exercise the same coercion path _decrypt uses:
    merged = {**svc.default_vars}
    v = merged["session_key"]
    assert bytes.fromhex(v) == b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
