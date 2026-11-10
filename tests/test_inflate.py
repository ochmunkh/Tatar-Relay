"""`inflate` codec — zlib / raw DEFLATE, reversible, capped (Content-Encoding: deflate)."""
import zlib
import pytest

from tatar_relay.steps.base import build_step
from tatar_relay.context import Context
from tatar_relay.errors import DecryptError


def test_inflate_zlib_roundtrip():
    step = build_step({"inflate": {}})
    ctx = Context()
    pt = b'{"hello":"world"}' * 10
    wire = step.backward(pt, ctx)
    assert wire != pt
    assert step.forward(wire, ctx) == pt


def test_inflate_raw_roundtrip():
    step = build_step({"inflate": {"raw": True}})
    ctx = Context()
    pt = b"abc" * 100
    assert step.forward(step.backward(pt, ctx), ctx) == pt


def test_inflate_matches_stdlib_zlib():
    step = build_step({"inflate": {}})
    data = b"the quick brown fox " * 50
    assert step.forward(zlib.compress(data), Context()) == data


def test_inflate_bad_data_is_decode_failed():
    step = build_step({"inflate": {}})
    with pytest.raises(DecryptError) as e:
        step.forward(b"not-really-zlib-\x00\x01\x02", Context())
    assert e.value.category == "decode_failed"


def test_inflate_cap_enforced():
    step = build_step({"inflate": {"max_size": 100}})
    big = zlib.compress(b"A" * 10000)
    with pytest.raises(DecryptError) as e:
        step.forward(big, Context())
    assert e.value.category == "decode_failed"
    assert "cap" in e.value.message
