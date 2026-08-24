import pytest

from tatar_relay.variables import Renderer, VarStore, json_path_get
from tatar_relay.errors import DecryptError


def test_single_token_returns_raw_value():
    vs = VarStore(); vs.set("session_key", b"\x00\x01\x02")
    assert Renderer(vs).render("${session_key}") == b"\x00\x01\x02"


def test_concat_template_is_string():
    vs = VarStore(); vs.set("a", "X"); vs.set("b", "Y")
    assert Renderer(vs).render("${a}-${b}") == "X-Y"


def test_random_hex_and_now():
    r = Renderer(VarStore())
    assert len(r.render("${random_hex(8)}")) == 16
    assert r.render("${now_ms}").isdigit()


def test_unknown_var_raises():
    with pytest.raises(DecryptError):
        Renderer(VarStore()).render("${nope}")


def test_live_var_recomputes():
    vs = VarStore()
    seq = iter([1, 2, 3])
    vs.set_live("counter", lambda: next(seq))
    assert vs.get("counter") == 1
    assert vs.get("counter") == 2


def test_json_path():
    obj = {"session": {"token": "abc"}}
    assert json_path_get(obj, "$.session.token") == "abc"
    with pytest.raises(KeyError):
        json_path_get(obj, "$.session.missing")
