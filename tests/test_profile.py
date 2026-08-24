import pytest

from tatar_relay import Profile
from tatar_relay.errors import ProfileError, ScopeViolation


def test_scope_fail_closed():
    with pytest.raises(ProfileError):
        Profile.loads("""
name: no-scope
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
""")


def test_type_mismatch_at_load():
    # gunzip (BYTES in) after as_json (JSON out) is a type error
    with pytest.raises(ProfileError):
        Profile.loads("""
name: bad-types
scope: { hosts: [ "x.example.com" ] }
request:
  transform:
    - base64_decode
    - as_json
    - gunzip
""")


def test_python_hook_rejected_when_untrusted():
    with pytest.raises(ProfileError):
        Profile.loads("""
name: sneaky
scope: { hosts: [ "x.example.com" ] }
request:
  transform:
    - python: { file: evil.py, forward: f, backward: g }
""")


def test_scope_enforcement():
    p = Profile.loads("""
name: scoped
scope: { hosts: [ "api\\\\.example\\\\.com$" ], paths: [ "^/v2/" ] }
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
""")
    p.check_scope("api.example.com", "/v2/pay")           # ok
    with pytest.raises(ScopeViolation):
        p.check_scope("evil.com", "/v2/pay")
    with pytest.raises(ScopeViolation):
        p.check_scope("api.example.com", "/admin")
