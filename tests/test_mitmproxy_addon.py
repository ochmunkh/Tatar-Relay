"""The mitmproxy addon must SHOW a feed() failure, not swallow it.

`Profile.feed()` raises `extraction_failed` when the handshake message arrived
but none of the var's locate strategies matched. `response()` is feed()'s only
production caller, and it used to wrap the call in `except RelayError: pass` —
so the diagnostic existed for direct API callers and for the unit tests, and for
nobody actually running the proxy. That is the whole point of the category, so
these tests pin the warning reaching `ctx.log`.

mitmproxy is deliberately NOT a dependency of this project (the addon is loaded
by the operator's own mitmdump), so the module is imported against a stub
`mitmproxy` package built here. Nothing is installed and nothing is added to
pyproject.
"""
import importlib
import sys
import types

import pytest

PROFILE = """
name: addon-feed
scope: { hosts: [ "api.example.com" ], paths: [ "^/.*" ] }
vars:
  session_key:
    from: extraction
    source: response
    match: "^/auth/handshake$"
    locate: [ { json_path: "$.sk" } ]
request:
  envelope: { locate: [ { in: raw } ] }
  transform: [ base64_decode ]
"""

# An extraction var with NO `match:` regex — re-checked on every in-scope
# response, which is the case that makes repeat-collapsing matter.
PROFILE_NO_MATCH = PROFILE.replace('    match: "^/auth/handshake$"\n', "")


class _Log:
    """Stand-in for mitmproxy's ctx.log."""

    def __init__(self) -> None:
        self.warns: list = []
        self.infos: list = []

    def warn(self, m) -> None:
        self.warns.append(str(m))

    def info(self, m) -> None:
        self.infos.append(str(m))

    def error(self, m) -> None:
        self.warns.append(str(m))


class _Req:
    def __init__(self, host: str, path: str) -> None:
        self.host, self.path = host, path
        self.method, self.url = "POST", f"https://{host}{path}"
        self.headers: dict = {}
        self.raw_content = b""


class _Resp:
    def __init__(self, body: bytes) -> None:
        self.headers: dict = {}
        self.raw_content = body


class _Flow:
    def __init__(self, path: str, body: bytes, host: str = "api.example.com") -> None:
        self.request = _Req(host, path)
        self.response = _Resp(body)


def _load(tmp_path, monkeypatch, profile_yaml: str = PROFILE):
    """Import the addon fresh against a stub mitmproxy; return (addon, log)."""
    prof = tmp_path / "addon.yaml"
    prof.write_text(profile_yaml, encoding="utf-8")
    monkeypatch.setenv("TATAR_RELAY_PROFILE", str(prof))

    log = _Log()
    pkg = types.ModuleType("mitmproxy")
    ctx_mod = types.ModuleType("mitmproxy.ctx")
    ctx_mod.log = log
    http_mod = types.ModuleType("mitmproxy.http")
    http_mod.HTTPFlow = _Flow
    pkg.ctx, pkg.http = ctx_mod, http_mod
    for name, mod in (("mitmproxy", pkg), ("mitmproxy.ctx", ctx_mod),
                      ("mitmproxy.http", http_mod)):
        monkeypatch.setitem(sys.modules, name, mod)
    # Force a fresh import: `addons = [TatarRelay()]` runs at module level, and
    # monkeypatch restores sys.modules (including this deletion) afterwards.
    monkeypatch.delitem(sys.modules, "tatar_relay.frontends.mitmproxy_addon",
                        raising=False)
    mod = importlib.import_module("tatar_relay.frontends.mitmproxy_addon")
    return mod.addons[0], log


@pytest.fixture
def addon(tmp_path, monkeypatch):
    return _load(tmp_path, monkeypatch)


def test_a_failed_extraction_reaches_the_operator(addon):
    """The regression this file exists for: `except RelayError: pass`."""
    relay, log = addon
    relay.response(_Flow("/auth/handshake", b'{"nope": 1}'))
    assert log.warns, "feed() failure was swallowed — the operator sees nothing"
    line = log.warns[0]
    assert "extraction_failed" in line          # the category, not a bare string
    assert "'session_key'" in line              # names the var that did not resolve
    assert "/auth/handshake" in line            # and the message it was looked for on


def test_a_successful_extraction_is_silent_and_sets_the_var(addon):
    relay, log = addon
    relay.response(_Flow("/auth/handshake", b'{"sk": "s3cret"}'))
    assert log.warns == []
    assert relay._vars.get("session_key") == "s3cret"


def test_an_out_of_scope_response_is_not_warned_about(addon):
    relay, log = addon
    relay.response(_Flow("/auth/handshake", b'{"nope": 1}',
                         host="evil.attacker.example"))
    assert log.warns == []


def test_a_bad_profile_regex_also_reaches_the_operator(tmp_path, monkeypatch):
    """config_error from `_search` travels the same path as extraction_failed."""
    relay, log = _load(tmp_path, monkeypatch, PROFILE.replace(
        'locate: [ { json_path: "$.sk" } ]', 'locate: [ { regex: "([unclosed" } ]'))
    relay.response(_Flow("/auth/handshake", b"anything"))
    assert log.warns and "config_error" in log.warns[0]
    assert "'session_key'" in log.warns[0]


def test_repeats_are_collapsed_but_a_recurrence_is_reported_again(tmp_path,
                                                                 monkeypatch):
    relay, log = _load(tmp_path, monkeypatch, PROFILE_NO_MATCH)
    for _ in range(5):
        relay.response(_Flow("/api/thing", b'{"nope": 1}'))
    assert len(log.warns) == 1, "one warning per response would bury the first"

    # A success clears the suppression, so the next failure is reported again.
    relay.response(_Flow("/api/thing", b'{"sk": "s3cret"}'))
    relay.response(_Flow("/api/thing", b'{"nope": 1}'))
    assert len(log.warns) == 2


def test_the_addon_never_raises_out_of_response(addon):
    """Contract: a frontend logs and passes the message through, never breaks it."""
    relay, _ = addon
    for body in (b'{"nope": 1}', b"not json at all", b"\xff\xfe", b"{}"):
        relay.response(_Flow("/auth/handshake", body))  # must not raise
