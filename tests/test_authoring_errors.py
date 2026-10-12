"""The four common authoring mistakes must report, not raise.

The profile-authoring loop *is* the product, and `validate` is the one command
whose whole job is to turn a wrong profile into an actionable message. These four
paths bypassed all of it and exited with a raw Python traceback, so a first-time
user's first mistake looked like a crash in the tool rather than a mistake in
their file:

  * a step-name typo          -> ValueError: unknown step: base64_dcode
  * a missing profile         -> FileNotFoundError
  * malformed YAML            -> yaml.parser.ParserError
  * --var session_key=hunter2 -> ValueError: non-hexadecimal number found ...

Each now exits with one line naming the mistake and, where possible, the fix.
"""
import pytest

from tatar_relay import Profile
from tatar_relay.cli import main
from tatar_relay.errors import ProfileError
from tatar_relay.steps.base import build_step, known_steps

GOOD = """
name: ok
scope: { hosts: [ "api\\\\.example\\\\.com$" ] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
"""


def _profile(tmp_path, text=GOOD, name="p.yaml"):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return str(f)


# ---- 1. a step-name typo --------------------------------------------------

def test_unknown_step_is_a_profile_error_with_a_suggestion():
    with pytest.raises(ProfileError) as ei:
        build_step("base64_dcode")
    msg = str(ei.value)
    assert "unknown step: base64_dcode" in msg
    assert "did you mean 'base64_decode'?" in msg
    assert "base64_decode" in msg


def test_unknown_step_lists_the_vocabulary_when_nothing_is_close():
    with pytest.raises(ProfileError) as ei:
        build_step("totally_unrelated_zzz")
    assert "known:" in str(ei.value)


def test_invalid_step_spec_is_a_profile_error():
    with pytest.raises(ProfileError) as ei:
        build_step({"a": 1, "b": 2})          # two keys is not a step
    assert "invalid step spec" in str(ei.value)


def test_validate_reports_a_step_typo(tmp_path, capsys):
    path = _profile(tmp_path, GOOD.replace("base64_decode", "base64_dcode"))
    assert main(["validate", path]) == 1
    out = capsys.readouterr().out
    assert out.startswith("✗ ")
    assert "base64_dcode" in out and "did you mean" in out


def test_steps_subcommand_prints_the_vocabulary(capsys):
    """`relay steps` gives known_steps() its first caller."""
    assert main(["steps"]) == 0
    out = capsys.readouterr().out
    for name in known_steps():
        assert name in out


# ---- 2. a missing profile -------------------------------------------------

def test_missing_profile_is_a_profile_error(tmp_path):
    with pytest.raises(ProfileError) as ei:
        Profile.load(str(tmp_path / "nope.yaml"))
    assert "nope.yaml" in str(ei.value)
    assert "cannot read profile" in str(ei.value)


def test_validate_reports_a_missing_profile(tmp_path, capsys):
    assert main(["validate", str(tmp_path / "nope.yaml")]) == 1
    assert "nope.yaml" in capsys.readouterr().out


# ---- 3. malformed YAML ----------------------------------------------------

def test_malformed_yaml_is_a_profile_error_with_a_line_number(tmp_path):
    path = _profile(tmp_path, "name: x\nscope: { hosts: [ a }\n")
    with pytest.raises(ProfileError) as ei:
        Profile.load(path)
    msg = str(ei.value)
    assert "invalid YAML" in msg
    assert "line 2" in msg


def test_non_mapping_profile_is_a_profile_error(tmp_path):
    path = _profile(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ProfileError) as ei:
        Profile.load(path)
    assert "must be a YAML mapping" in str(ei.value)


# ---- 4. a bad --var ------------------------------------------------------

def test_non_hex_var_names_the_var_and_the_prefixes(tmp_path, capsys):
    path = _profile(tmp_path)
    wire = tmp_path / "w.bin"
    wire.write_bytes(b"YWJj")
    rc = main(["run", path, "-i", str(wire), "--var", "session_key=hunter2"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--var session_key" in err
    assert "is not hex" in err
    for prefix in ("str:", "b64:", "hex:"):
        assert prefix in err


@pytest.mark.parametrize("value,expected", [
    ("str:hunter2", b"hunter2"),
    ("b64:aGk=", b"hi"),
    ("hex:6465", b"de"),
    ("6465", b"de"),
])
def test_var_prefixes_still_work(tmp_path, value, expected):
    from tatar_relay.cli import _build_ctx
    ctx = _build_ctx(Profile.load(_profile(tmp_path)), "", [f"k={value}"])
    assert ctx.vars.get("k") == expected


# ---- 5. preview against a channel the profile does not define ------------

def test_preview_without_that_pipeline_is_reported(tmp_path, capsys):
    path = _profile(tmp_path)
    wire = tmp_path / "w.bin"
    wire.write_bytes(b"YWJj")
    rc = main(["preview", path, "-i", str(wire), "--channel", "response"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no 'response' pipeline" in err
    assert "request" in err          # says what the profile does define


# ---- 6. a declared var that never resolves -------------------------------

TWO_VARS = """
name: two-vars
scope: { hosts: [ "api.example.com" ] }
vars:
  good: { from: extraction, source: response, locate: [ { json_path: "$.a" } ] }
  bad:  { from: extraction, source: response, locate: [ { json_path: "$.nope" } ] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
"""


def test_a_var_that_never_resolves_is_named(tmp_path):
    """Silently returning None surfaced later as tag_mismatch/padding, pointing
    the operator at the cipher step instead of at the handshake."""
    from tatar_relay.context import HttpMessage
    from tatar_relay.errors import DecryptError
    from tatar_relay.variables import VarStore

    p = Profile.loads(TWO_VARS)
    with pytest.raises(DecryptError) as ei:
        p.feed(HttpMessage(path="/h", body=b'{"a":"V"}'), "response", VarStore())
    assert ei.value.category == "extraction_failed"
    assert "'bad'" in ei.value.message
    assert "/h" in ei.value.message


def test_vars_that_do_resolve_are_still_set(tmp_path):
    """One missing field must not cost the operator the vars that did resolve."""
    from tatar_relay.context import HttpMessage
    from tatar_relay.errors import DecryptError
    from tatar_relay.variables import VarStore

    vs = VarStore()
    with pytest.raises(DecryptError):
        Profile.loads(TWO_VARS).feed(
            HttpMessage(path="/h", body=b'{"a":"V"}'), "response", vs)
    assert vs.get("good") == "V"


def test_a_bad_profile_regex_names_the_var():
    from tatar_relay.context import HttpMessage
    from tatar_relay.errors import DecryptError
    from tatar_relay.variables import VarStore

    p = Profile.loads("""
name: bad-regex
scope: { hosts: [ "api.example.com" ] }
vars:
  k: { from: extraction, source: response, locate: [ { regex: "([unclosed" } ] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
""")
    with pytest.raises(DecryptError) as ei:
        p.feed(HttpMessage(path="/h", body=b"x"), "response", VarStore())
    assert ei.value.category == "config_error"
    assert "'k'" in ei.value.message and "bad regex" in ei.value.message


# ---- 7. main's backstops -------------------------------------------------

def test_unreadable_input_is_reported_not_raised(tmp_path, capsys):
    path = _profile(tmp_path)
    rc = main(["run", path, "-i", str(tmp_path / "missing.bin")])
    assert rc == 2
    assert "missing.bin" in capsys.readouterr().err
