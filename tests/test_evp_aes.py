"""EVP_BytesToKey / AES passphrase-mode step (`evp_aes_decrypt`).

The pinned vector is generated INDEPENDENTLY with OpenSSL
(`openssl enc -aes-256-cbc -md md5 -S <salt> -pass pass:<phrase>`), which uses
the same EVP_BytesToKey(MD5) KDF — so a pass proves we match the real thing,
not just ourselves. Synthetic passphrase/data only.
"""
import base64
import json

import pytest

from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.steps.base import build_step
from tatar_relay.steps.kdf import evp_bytes_to_key
from tatar_relay.variables import VarStore
from tatar_relay.errors import DecryptError


def _ctx(ecode="1234") -> Context:
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("ecode", ecode)
    c.vars = vs
    return c


def test_evp_bytes_to_key_matches_openssl():
    # openssl: key/iv for pass "1234", salt 0011223344556677
    key, iv = evp_bytes_to_key(b"1234", bytes.fromhex("0011223344556677"), 32, 16, __import__("hashlib").md5)
    assert key.hex() == "4d9752d29a9e34efd81897a9a957fd6662c96c5dbda9bb9d754c103f612eda10"
    assert iv.hex() == "35ea0d8540aec40f9367e7b1758880ca"


def test_evp_aes_decrypt_openssl_vector():
    step = build_step({"evp_aes_decrypt": {"passphrase": "${ecode}"}})
    body = json.dumps({
        "ct": "kAnL338CsJ10lyrveZoqhSv3UiJmLV5DNdIfEEIlMhJa79bJhHUnUl+tHsHFj7z6",
        "iv": "35EA0D8540AEC40F9367E7B1758880CA",   # decorative — KDF re-derives it
        "s":  "0011223344556677",
    }).encode()
    out = step.forward(body, _ctx("1234"))
    assert json.loads(out) == {"call": "get_balance", "amount": 100}


def test_evp_aes_wrong_passphrase_fails():
    step = build_step({"evp_aes_decrypt": {"passphrase": "${ecode}"}})
    body = json.dumps({
        "ct": "kAnL338CsJ10lyrveZoqhSv3UiJmLV5DNdIfEEIlMhJa79bJhHUnUl+tHsHFj7z6",
        "s":  "0011223344556677",
    }).encode()
    with pytest.raises(DecryptError):
        step.forward(body, _ctx("wrong-code"))


def test_evp_aes_step_roundtrip():
    step = build_step({"evp_aes_decrypt": {"passphrase": "${ecode}"}})
    pt = json.dumps({"x": 1, "y": "z"}).encode()
    wire = step.backward(pt, _ctx())      # fresh salt each time
    assert step.forward(wire, _ctx()) == pt


def test_evp_aes_missing_passphrase_rejected():
    with pytest.raises(DecryptError):
        build_step({"evp_aes_decrypt": {}})


PROFILE = """
name: evp-aes-passphrase
scope: { hosts: [ "api.example.com" ] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform:
    - evp_aes_decrypt: { passphrase: "${ecode}" }
    - as_json
  reseal:
    - serialize: { mode: compact }
response:
  envelope: { locate: [ { in: raw } ] }
  transform:
    - evp_aes_decrypt: { passphrase: "${ecode}" }
    - as_json
"""


def test_evp_aes_profile_roundtrip():
    eng = Engine(Profile.loads(PROFILE))
    c = _ctx()
    plain = {"call": "get_balance", "amount": 100}
    wire = eng.encrypt("request", plain, c)
    assert json.loads(wire.decode()).keys() >= {"ct", "iv", "s"}   # EVP envelope shape
    assert eng.decrypt("request", wire, c) == plain
