"""Fuzz / hostile-input tests.

Round-trip and error-category tests prove the happy path; these prove the
pipeline degrades *safely* on hostile input. Truncated blobs, malformed UTF-8,
non-hex / non-base64 junk, and a decompression bomb must all raise a
categorized ``DecryptError`` — never an uncaught exception or an unbounded
allocation. Synthetic data only.
"""
import base64
import gzip
import os

import pytest

from tatar_relay import Context, HttpMessage
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore
from tatar_relay.errors import DecryptError


def _ctx(**vars_) -> Context:
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore()
    for k, v in vars_.items():
        vs.set(k, v)
    c.vars = vs
    return c


# A spread of hostile blobs: empty, single byte, invalid UTF-8, junk that looks
# textual, odd-length hex, random bytes, and a long run.
HOSTILE = [
    b"",
    b"\x00",
    b"\xff\xfe\xfd\xfc",
    b"not-base64-!!!@@@",
    b"deadbeef0",              # odd-length hex
    os.urandom(64),
    b"A" * 10_000,
]


def _must_not_crash(step, blob, ctx):
    """A hostile blob may decode or may raise DecryptError — but never any other
    exception type."""
    try:
        step.forward(blob, ctx)
    except DecryptError:
        pass


@pytest.mark.parametrize("blob", HOSTILE)
def test_base64_decode_hostile(blob):
    _must_not_crash(build_step({"base64_decode": {}}), blob, _ctx())


@pytest.mark.parametrize("blob", HOSTILE)
def test_hex_decode_hostile(blob):
    _must_not_crash(build_step({"hex_decode": {}}), blob, _ctx())


@pytest.mark.parametrize("blob", HOSTILE)
def test_gunzip_hostile(blob):
    _must_not_crash(build_step({"gunzip": {}}), blob, _ctx())


@pytest.mark.parametrize("blob", HOSTILE)
def test_nonce_body_hostile(blob):
    _must_not_crash(build_step({"nonce_body": {"nonce_length": 12}}), blob, _ctx())


@pytest.mark.parametrize("blob", HOSTILE)
def test_evp_aes_hostile(blob):
    _must_not_crash(build_step({"evp_aes_decrypt": {"passphrase": "${ecode}"}}),
                    blob, _ctx(ecode=b"1234"))


# ── specific safety guarantees ────────────────────────────────────────────

def test_gunzip_truncated_stream_raises():
    good = gzip.compress(b"hello world " * 200)
    step = build_step({"gunzip": {}})
    with pytest.raises(DecryptError):
        step.forward(good[: len(good) // 2], _ctx())


def test_gunzip_decompression_bomb_capped():
    # ~4 MiB of zeros compresses to a few KB; a 1 MiB cap must reject it.
    bomb = gzip.compress(b"\x00" * (4 * 1024 * 1024))
    step = build_step({"gunzip": {"max_size": 1 << 20}})
    with pytest.raises(DecryptError):
        step.forward(bomb, _ctx())


def test_gunzip_within_cap_roundtrip():
    payload = b"B" * (512 * 1024)
    step = build_step({"gunzip": {"max_size": 1 << 20}})
    assert step.forward(gzip.compress(payload), _ctx()) == payload


def test_base64_output_cap():
    blob = base64.b64encode(b"x" * 1000)
    step = build_step({"base64_decode": {"max_size": 16}})
    with pytest.raises(DecryptError):
        step.forward(blob, _ctx())


def test_evp_aes_malformed_fields_raise():
    step = build_step({"evp_aes_decrypt": {"passphrase": "${ecode}"}})
    with pytest.raises(DecryptError):
        step.forward(b'{"ct":"!!!not-base64","s":"zz"}', _ctx(ecode=b"1234"))


# ── typed key-prefix coercion (hmac_verify) ───────────────────────────────

def test_hmac_key_prefixes():
    from tatar_relay.steps.auth import _to_bytes
    assert _to_bytes("str:deadbeef") == b"deadbeef"       # forced UTF-8
    assert _to_bytes("hex:6465")     == b"de"             # forced hex
    assert _to_bytes("b64:aGk=")     == b"hi"             # forced base64
    assert _to_bytes("6465")         == b"de"             # bare hex (compat)
    assert _to_bytes("hello world")  == b"hello world"    # bare non-hex -> utf-8


def test_hmac_key_bad_prefix_raises():
    from tatar_relay.steps.auth import _to_bytes
    with pytest.raises(DecryptError):
        _to_bytes("hex:zzzz")
