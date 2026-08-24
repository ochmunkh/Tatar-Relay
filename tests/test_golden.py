"""Golden regression: a byte-stable wire must keep decrypting/encrypting the same.

Uses a deterministic profile (fixed IV, canonical serialize, no random/time) so
the output is reproducible. If a future change alters the byte layout, this test
fails loudly.
"""
import json
import os

from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.variables import VarStore

HERE = os.path.dirname(__file__)
GOLD = os.path.join(HERE, "golden")


def _ctx():
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore()
    vs.set("session_key", bytes(range(32)))
    vs.set("iv", bytes(range(16)))
    c.vars = vs
    return c


def test_golden_decrypt():
    p = Profile.load(os.path.join(GOLD, "golden.yaml"))
    eng = Engine(p)
    wire = open(os.path.join(GOLD, "req_01.wire"), "rb").read()
    expected = json.load(open(os.path.join(GOLD, "plain_01.json")))
    assert eng.decrypt("request", wire, _ctx()) == expected


def test_golden_encrypt_is_byte_stable():
    p = Profile.load(os.path.join(GOLD, "golden.yaml"))
    eng = Engine(p)
    expected_wire = open(os.path.join(GOLD, "req_01.wire"), "rb").read()
    plain = json.load(open(os.path.join(GOLD, "plain_01.json")))
    assert eng.encrypt("request", plain, _ctx()) == expected_wire
