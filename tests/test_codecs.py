from tatar_relay.context import Context
from tatar_relay.steps.base import build_step


def rt(step_spec, data):
    step = build_step(step_spec)
    ctx = Context()
    return step.backward(step.forward(data, ctx), ctx)


def test_base64_roundtrip():
    step = build_step("base64_decode")
    ctx = Context()
    assert step.forward("SGVsbG8=", ctx) == b"Hello"
    assert step.backward(b"Hello", ctx) == "SGVsbG8="


def test_hex_roundtrip():
    step = build_step("hex_decode")
    ctx = Context()
    assert step.forward("48656c6c6f", ctx) == b"Hello"
    assert step.backward(b"Hello", ctx) == "48656c6c6f"


def test_gzip_roundtrip():
    step = build_step("gunzip")
    ctx = Context()
    original = b"the quick brown fox" * 20
    compressed = step.backward(original, ctx)
    assert step.forward(compressed, ctx) == original
