"""schema_version (Profile v1, Frozen Contract #1) — additive + fail-closed."""
import pytest

from tatar_relay.profile import Profile, SCHEMA_VERSION
from tatar_relay.errors import ProfileError

BASE = '''name: t
scope: { hosts: ["api.example.com"] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
'''


def _load(extra: str = "") -> Profile:
    return Profile.loads(BASE + extra + "\n")


def test_default_is_current_version():
    assert _load().schema_version == SCHEMA_VERSION == 1


def test_explicit_current_version_ok():
    assert _load("schema_version: 1").schema_version == 1


def test_future_version_rejected_fail_closed():
    with pytest.raises(ProfileError) as e:
        _load("schema_version: 999")
    assert "newer than this build" in str(e.value)


def test_non_integer_version_rejected():
    with pytest.raises(ProfileError):
        _load('schema_version: "abc"')


def test_zero_version_rejected():
    with pytest.raises(ProfileError):
        _load("schema_version: 0")
