import os
import pytest

from tatar_relay.context import Context, HttpMessage
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore
from tatar_relay.errors import DecryptError

KEY = os.urandom(32)


def _ctx(key=KEY):
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("session_key", key)
    c.vars = vs
    return c


def test_chacha_roundtrip():
    step = build_step({"chacha20_decrypt": {"key": "${session_key}"}})
    plaintext = b'{"amount":100}'
    ct = step.backward(plaintext, _ctx())
    assert step.forward(ct, _ctx()) == plaintext


def test_chacha_wrong_key_tag_mismatch():
    step = build_step({"chacha20_decrypt": {"key": "${session_key}"}})
    ct = step.backward(b"secret", _ctx())
    with pytest.raises(DecryptError) as e:
        step.forward(ct, _ctx(os.urandom(32)))
    assert e.value.category == "tag_mismatch"


def test_chacha_wrong_key_size():
    step = build_step({"chacha20_decrypt": {"key": "${session_key}"}})
    with pytest.raises(DecryptError) as e:
        step.backward(b"x", _ctx(os.urandom(16)))  # 16 bytes invalid for chacha
    assert e.value.category == "wrong_key_size"
