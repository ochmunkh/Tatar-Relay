"""The scope gate must actually deny.

README advertises scope as **fail-closed**, and docs/architecture.md drew
`Profile.check_scope(host, path)` into the request flow (it now names the real
entry point, `Profile.authorize`) — but outside the
mitmproxy addon nothing called it: bridge.py built its Context from
`profile.scope.hosts[0]`, so the host being checked was the profile's own and
the check could never fail. These tests pin the wiring, not just the matcher:
an out-of-scope host must be refused on the bridge and on the CLI, and an
in-scope one must still be let through.
"""
import base64
from pathlib import Path

import pytest

from tatar_relay import Context, Engine, HttpMessage, Profile
from tatar_relay.bridge import BridgeService
from tatar_relay.errors import ScopeViolation
from tatar_relay.variables import VarStore

ROOT = Path(__file__).resolve().parent.parent

PROFILE = """
name: scoped
scope:
  hosts: [ "api\\\\.example\\\\.com$" ]
  paths: [ "^/v2/" ]
request:
  envelope: { locate: [ { in: json_field, field: "data" } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: cbc, key: "${session_key}", iv: { source: prefix, length: 16 } }
    - as_json
  reseal:
    - serialize: { mode: preserve }
"""

KEY = bytes(range(32))


def _wire() -> str:
    eng = Engine(Profile.loads(PROFILE))
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("session_key", KEY); c.vars = vs
    return base64.b64encode(eng.encrypt("request", {"amount": 1000}, c)).decode()


def _svc():
    svc = BridgeService()
    svc.add_profile(Profile.loads(PROFILE))
    return svc


def _decrypt(svc, **extra):
    msg = {"method": "decrypt", "profile": "scoped", "channel": "request",
           "wire": _wire(), "vars": {"session_key": KEY.hex()}, "flow_id": "f1"}
    msg.update(extra)
    return svc.handle(msg)


# ---- the gate denies -------------------------------------------------------

def test_bridge_refuses_an_out_of_scope_host():
    out = _decrypt(_svc(), host="evil.attacker.example")
    assert out["ok"] is False
    assert out["error"]["category"] == "scope_violation"
    assert "evil.attacker.example" in out["error"]["message"]
    assert "plaintext" not in out          # nothing was decrypted


def test_bridge_refuses_an_out_of_scope_path_when_one_is_supplied():
    out = _decrypt(_svc(), host="api.example.com", path="/admin")
    assert out["ok"] is False
    assert out["error"]["category"] == "scope_violation"


# ---- ...without breaking the frontends that do supply a host ---------------

def test_bridge_allows_an_in_scope_host_and_path():
    out = _decrypt(_svc(), host="api.example.com", path="/v2/pay")
    assert out["ok"] and out["plaintext"] == {"amount": 1000}


def test_bridge_allows_a_host_only_frontend_despite_a_paths_regex():
    """A frontend that knows the host but not the path must not be refused.

    Checking the host with the path defaulted to "/" would reject every profile
    carrying a `paths:` regex — including both shipped examples — which is why
    the gate has to treat a missing path as "host only".
    """
    out = _decrypt(_svc(), host="api.example.com")
    assert out["ok"] and out["plaintext"] == {"amount": 1000}


def test_bridge_without_a_host_is_unchanged():
    """Contract #5 stays backward compatible: host/path are optional."""
    out = _decrypt(_svc())
    assert out["ok"] and out["plaintext"] == {"amount": 1000}


# ---- the Profile-level API the frontends call ------------------------------

def test_authorize_host_only_vs_host_and_path():
    p = Profile.loads(PROFILE)
    p.authorize("api.example.com")                  # host only -> allowed
    p.authorize("api.example.com", "/v2/pay")       # both -> allowed
    with pytest.raises(ScopeViolation):
        p.authorize("evil.attacker.example")
    with pytest.raises(ScopeViolation):
        p.authorize("api.example.com", "/admin")


def test_shipped_examples_authorize_host_only():
    """Regression guard: `relay run <example> --host api.example.com` must work."""
    for name in ("acme-bank-mobile", "full-envelope", "evp-aes-passphrase"):
        Profile.load(str(ROOT / "examples" / f"{name}.yaml")).authorize(
            "api.example.com")


def test_cli_run_refuses_an_out_of_scope_host(tmp_path, capsys):
    from tatar_relay.cli import main
    prof = tmp_path / "scoped.yaml"
    prof.write_text(PROFILE, encoding="utf-8")
    wire = tmp_path / "wire.bin"
    wire.write_bytes(base64.b64decode(_wire()))

    rc = main(["run", str(prof), "-i", str(wire),
               "--host", "evil.attacker.example",
               "--var", f"session_key={KEY.hex()}"])
    assert rc == 2
    err = capsys.readouterr()
    assert "outside" in err.err and "evil.attacker.example" in err.err
    assert "amount" not in err.out            # no plaintext leaked to stdout
