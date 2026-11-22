"""Bridge transport hardening — the tool's own attack surface.

The bridge decrypts and reseals with the operator's keys, so it must never
become an oracle for the network or for a web page open in the test browser.
"""
import http.client
import json
import threading

import pytest

from tatar_relay.bridge import (
    BridgeService, MAX_REQUEST_BYTES, is_loopback, make_server,
    require_safe_bind, screen_request)
from tatar_relay.errors import RelayError


# -- S1: bind policy ---------------------------------------------------------
@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.5", "localhost", "::1"])
def test_loopback_bind_needs_no_token(host):
    require_safe_bind(host, None)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::", "relay.example.com"])
def test_non_loopback_bind_without_token_is_refused(host):
    with pytest.raises(RelayError):
        require_safe_bind(host, None)


def test_non_loopback_bind_with_token_is_allowed():
    require_safe_bind("0.0.0.0", "s3cret")


def test_is_loopback():
    assert is_loopback("127.0.0.1") and is_loopback("[::1]") and is_loopback("LOCALHOST")
    assert not is_loopback("10.0.0.1") and not is_loopback("evil.example")


# -- S2/S3: request screening ------------------------------------------------
def _h(**kw):
    return {k.replace("_", "-"): v for k, v in kw.items()}


def test_browser_origin_is_refused():
    v = screen_request(_h(Origin="https://evil.example", Host="127.0.0.1:8799"),
                       bind_host="127.0.0.1")
    assert v and v[0] == 403


@pytest.mark.parametrize("host_hdr", ["evil.example", "evil.example:8799", "10.0.0.7:8799"])
def test_dns_rebinding_host_is_refused(host_hdr):
    v = screen_request({"Host": host_hdr}, bind_host="127.0.0.1")
    assert v and v[0] == 403


@pytest.mark.parametrize("host_hdr", ["127.0.0.1:8799", "localhost", "[::1]:8799", ""])
def test_loopback_host_is_accepted(host_hdr):
    assert screen_request({"Host": host_hdr, "Content-Length": "10"},
                          bind_host="127.0.0.1") is None


def test_remote_bind_skips_host_check():
    # Bound beyond loopback (token required by S1): clients use real hostnames.
    assert screen_request({"Host": "relay.lan:8799"}, bind_host="0.0.0.0") is None


def test_oversized_body_is_refused():
    v = screen_request({"Content-Length": str(MAX_REQUEST_BYTES + 1)}, bind_host="127.0.0.1")
    assert v and v[0] == 413


@pytest.mark.parametrize("cl", ["abc", "-5"])
def test_bad_content_length_is_refused(cl):
    v = screen_request({"Content-Length": cl}, bind_host="127.0.0.1")
    assert v and v[0] == 400


# -- S4: bounded ctx store + strong tokens -----------------------------------
def test_ctx_store_is_bounded_lru():
    svc = BridgeService(max_ctx=3)
    toks = [svc._remember(("e", i)) for i in range(5)]
    assert len(svc._ctx) == 3
    assert toks[0] not in svc._ctx and toks[1] not in svc._ctx
    assert all(t in svc._ctx for t in toks[2:])


def test_ctx_token_is_128_bit():
    tok = BridgeService()._remember(("e",))
    assert tok.startswith("t-") and len(tok) == 2 + 32


# -- wiring: a real server on an ephemeral port -------------------------------
@pytest.fixture
def server():
    srv = make_server(BridgeService(), host="127.0.0.1", port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _post(port, body=b'{"method":"nope"}', headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    c.request("POST", "/", body=body, headers=h)
    r = c.getresponse()
    data = json.loads(r.read() or b"{}")
    c.close()
    return r.status, data


def test_live_server_accepts_burp_style_request(server):
    status, data = _post(server)
    assert status == 200 and data["ok"] is False   # unknown method, but served


def test_live_server_refuses_browser_request(server):
    status, data = _post(server, headers={"Origin": "https://evil.example"})
    assert status == 403 and data["ok"] is False


def test_live_server_refuses_rebinding_host(server):
    status, _ = _post(server, headers={"Host": "evil.example"})
    assert status == 403


def test_live_server_rejects_non_object_json(server):
    status, data = _post(server, body=b"[1,2,3]")
    assert status == 400 and data["ok"] is False


# -- capture sidecar never leaves loopback -----------------------------------
def test_capture_sidecar_stays_on_loopback():
    from tatar_relay.bridge import capture_bind_host
    assert capture_bind_host("127.0.0.1") == "127.0.0.1"
    assert capture_bind_host("::1") == "::1"
    assert capture_bind_host("0.0.0.0") == "127.0.0.1"
    assert capture_bind_host("192.168.1.5") == "127.0.0.1"
