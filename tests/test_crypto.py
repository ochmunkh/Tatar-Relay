import pytest

from tatar_relay.context import Context
from tatar_relay.errors import DecryptError
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore


def ctx_with_key(key: bytes) -> Context:
    c = Context()
    vs = VarStore(); vs.set("session_key", key)
    c.vars = vs
    return c


def test_aes_cbc_roundtrip():
    key = bytes(range(32))
    step = build_step({"aes_decrypt": {"mode": "cbc", "key": "${session_key}",
                                       "iv": {"source": "prefix", "length": 16}}})
    ctx = ctx_with_key(key)
    pt = b'{"amount":1000}'
    wire = step.backward(pt, ctx)
    assert step.forward(wire, ctx) == pt


def test_aes_gcm_roundtrip():
    key = bytes(range(16))
    step = build_step({"aes_decrypt": {"mode": "gcm", "key": "${session_key}"}})
    ctx = ctx_with_key(key)
    pt = b'{"ok":true}'
    wire = step.backward(pt, ctx)
    assert step.forward(wire, ctx) == pt


def test_cbc_wrong_key_is_padding_error():
    step = build_step({"aes_decrypt": {"mode": "cbc", "key": "${session_key}",
                                       "iv": {"source": "prefix", "length": 16}}})
    wire = step.backward(b'{"amount":1000}', ctx_with_key(bytes(range(32))))
    with pytest.raises(DecryptError) as ei:
        step.forward(wire, ctx_with_key(bytes([9]) * 32))
    assert ei.value.category == "padding"


def test_gcm_wrong_key_is_tag_mismatch():
    step = build_step({"aes_decrypt": {"mode": "gcm", "key": "${session_key}"}})
    wire = step.backward(b'{"ok":true}', ctx_with_key(bytes(range(16))))
    with pytest.raises(DecryptError) as ei:
        step.forward(wire, ctx_with_key(bytes([9]) * 16))
    assert ei.value.category == "tag_mismatch"


def test_wrong_key_size():
    step = build_step({"aes_decrypt": {"mode": "cbc", "key": "${session_key}"}})
    with pytest.raises(DecryptError) as ei:
        step.backward(b"x", ctx_with_key(b"tooshort"))
    assert ei.value.category == "wrong_key_size"
