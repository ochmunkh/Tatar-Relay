"""Golden corpus across target classes — byte-stable regression guards.

Each case pins a wire for a deterministic profile (fixed IV / nonce-prefix, no
random, no timestamp). `decrypt(wire) == plain` for every case; `encrypt(plain)
== wire` for the ones whose encrypt path is deterministic. AEAD encrypt uses a
random nonce by design, so AES-GCM is decrypt-only here. Synthetic data only.
"""
import json
import os

import pytest

from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.variables import VarStore

HERE = os.path.dirname(__file__)
GOLD = os.path.join(HERE, "golden")

# (name, encrypt_is_byte_stable)
CASES = [
    ("golden-gzip-cbc", False),  # gzip header carries mtime -> encrypt not byte-stable (decrypt + round-trip only)
    ("golden-hex-cbc", True),    # hex + AES-CBC (fixed IV)
    ("golden-gcm", False),       # base64 + AES-GCM nonce-prefix (random nonce on encrypt)
    ("golden-deflate-cbc", False),  # base64 + AES-CBC + DEFLATE (inflate); zlib bytes vary -> decrypt + round-trip only
]


def _ctx():
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore()
    vs.set("session_key", bytes(range(32)))
    vs.set("iv", bytes(range(16)))
    c.vars = vs
    return c


def _load(name):
    eng = Engine(Profile.load(os.path.join(GOLD, name + ".yaml")))
    wire = open(os.path.join(GOLD, name + ".wire"), "rb").read()
    plain = json.load(open(os.path.join(GOLD, name + ".json")))
    return eng, wire, plain


@pytest.mark.parametrize("name,_stable", CASES)
def test_golden_decrypt(name, _stable):
    eng, wire, plain = _load(name)
    assert eng.decrypt("request", wire, _ctx()) == plain


@pytest.mark.parametrize("name", [n for n, stable in CASES if stable])
def test_golden_encrypt_is_byte_stable(name):
    eng, wire, plain = _load(name)
    assert eng.encrypt("request", plain, _ctx()) == wire


@pytest.mark.parametrize("name,_stable", CASES)
def test_golden_round_trip(name, _stable):
    eng, wire, plain = _load(name)
    assert eng.decrypt("request", eng.encrypt("request", plain, _ctx()), _ctx()) == plain
