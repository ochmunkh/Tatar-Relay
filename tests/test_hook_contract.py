"""The documented Python-hook signature is `(data, ctx)` — pin it.

steps/pyhook.py calls `fn(data, ctx)` and CONTRACTS.md #3 says so, but
docs/how-to-add-algorithm.md and docs/algorithms.md documented a third `params`
argument in five places, so the repo's only worked RSA-hybrid hook example could
not run: copying the documented signature verbatim gave

    [hook_error] hooks/x.py:decrypt raised TypeError:
    decrypt() missing 1 required positional argument: 'params'

`relay init` scaffolds the correct 2-arg form. This test makes the suite, not
just the prose, the thing that has to be updated if the arity ever changes.
"""
import pytest

from tatar_relay import Context, HttpMessage
from tatar_relay.errors import DecryptError
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore

TWO_ARG_HOOK = '''\
"""A hook written to the documented signature."""

def decrypt(data, ctx):
    return bytes(data)[::-1]


def encrypt(data, ctx):
    return bytes(data)[::-1]
'''

THREE_ARG_HOOK = '''\
"""A hook written to the signature the docs used to show."""

def decrypt(data, ctx, params):
    return bytes(data)[::-1]
'''


def _ctx() -> Context:
    c = Context(request=HttpMessage(host="api.example.com"))
    c.vars = VarStore()
    return c


def _hook(tmp_path, body: str) -> str:
    (tmp_path / "hooks").mkdir(exist_ok=True)
    f = tmp_path / "hooks" / "sig.py"
    f.write_text(body, encoding="utf-8")
    return str(f)


def test_two_arg_hook_is_what_the_engine_calls(tmp_path):
    step = build_step({"python": {"file": _hook(tmp_path, TWO_ARG_HOOK),
                                  "forward": "decrypt", "backward": "encrypt"}})
    assert step.forward(b"abc", _ctx()) == b"cba"
    assert step.backward(b"cba", _ctx()) == b"abc"


def test_a_three_arg_hook_fails_with_a_hook_error(tmp_path):
    """The old documented form: a categorized error, not a bare TypeError."""
    step = build_step({"python": {"file": _hook(tmp_path, THREE_ARG_HOOK),
                                  "forward": "decrypt"}})
    with pytest.raises(DecryptError) as ei:
        step.forward(b"abc", _ctx())
    assert ei.value.category == "hook_error"
    assert "params" in ei.value.message


@pytest.mark.parametrize("doc", [
    "docs/how-to-add-algorithm.md",
    "docs/algorithms.md",
])
def test_the_guides_do_not_document_a_third_hook_argument(doc):
    from pathlib import Path
    text = Path(__file__).resolve().parent.parent.joinpath(doc).read_text(encoding="utf-8")
    assert "params: dict" not in text, (
        f"{doc} documents a `params` argument that steps/pyhook.py never passes"
    )
