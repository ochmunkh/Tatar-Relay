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
    # The wire is a FIXED ciphertext, not one produced by step.backward().
    #
    # backward() picks a random IV, so every run decrypted different bytes under
    # the wrong key, and PKCS7 accepts a random final byte roughly 1 time in 256
    # -- the test failed about once every 40 runs. Measured, not theorised: 1
    # failure in 40 consecutive runs of the suite.
    #
    # This IV/ciphertext pair was chosen because decrypting it with the wrong key
    # below yields a final byte of 0x59, which is not a valid pad length, so the
    # padding error is guaranteed rather than probable.
    step = build_step({"aes_decrypt": {"mode": "cbc", "key": "${session_key}",
                                       "iv": {"source": "prefix", "length": 16}}})
    wire = bytes.fromhex(
        "00000000000000000000000000000000"          # IV
        "dec0931dbc7c6658fc09d85966bc4708"          # AES-256-CBC of {"amount":1000}
    )                                               # under key bytes(range(32))
    # Sanity: the RIGHT key still round-trips this exact wire, so the fixture is
    # a real ciphertext and not just bytes that happen to fail.
    assert step.forward(wire, ctx_with_key(bytes(range(32)))) == b'{"amount":1000}'
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
